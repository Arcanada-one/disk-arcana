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
requested_runner_id=''
github_token_file=''
validate_only=false
while (($#)); do
  case "$1" in
    --state-root)
      require_value "$1" "${2:-}"
      state_root="$2"
      shift 2
      ;;
    --runner-id)
      require_value "$1" "${2:-}"
      requested_runner_id="$2"
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
    *) die 64 "unknown option: $1" ;;
  esac
done

[[ -n "$state_root" ]] || die 64 'missing required option: --state-root'
[[ -n "$requested_runner_id" ]] || die 64 'missing required option: --runner-id'
[[ -n "$github_token_file" ]] || die 64 'missing required option: --github-token-file'
[[ "$requested_runner_id" =~ ^[1-9][0-9]{0,19}$ ]] || die 65 'runner ID is invalid'
[[ "$state_root" == /* && "$state_root" != / && -d "$state_root" && ! -L "$state_root" ]] ||
  die 65 'state root is unsafe'
[[ -f "$github_token_file" && ! -L "$github_token_file" ]] || die 65 'GitHub token file is unsafe'

test_mode=false
expected_uid=0
expected_gid=0
if [[ "${DISK_ARCANA_STAGE_BIND_TESTING:-}" == 1 ]]; then
  [[ "$(id -u)" != 0 ]] || die 65 'identity binding test mode is forbidden for root'
  [[ -n "${DISK_ARCANA_STAGE_BIND_API_RESPONSE:-}" ]] ||
    die 65 'identity binding test mode requires an API response fixture'
  [[ -n "${DISK_ARCANA_STAGE_BIND_GROUP_API_RESPONSE:-}" ]] ||
    die 65 'identity binding test mode requires a group API response fixture'
  test_mode=true
  expected_uid="$(id -u)"
  expected_gid="$(id -g)"
else
  [[ -z "${DISK_ARCANA_STAGE_BIND_TESTING:-}" &&
     -z "${DISK_ARCANA_STAGE_BIND_API_RESPONSE:-}" &&
     -z "${DISK_ARCANA_STAGE_BIND_GROUP_API_RESPONSE:-}" ]] ||
    die 65 'identity binding test controls are forbidden in production'
  [[ "$(id -u)" == 0 ]] || die 77 'identity binding requires root'
  [[ "$(dirname "$state_root")" == /var/lib/disk-arcana-stage ]] ||
    die 65 'state root is not canonical'
fi

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
manifest_runner_id=''
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
    runner_id) manifest_runner_id="$value" ;;
    *) die 65 'state manifest contains an unknown key' ;;
  esac
done <"$manifest"
[[ "${#manifest_seen[@]}" -eq 9 ]] || die 65 'state manifest is incomplete'
[[ "$guest_name" == disk-arcana-stage && "$manifest_state_root" == "$state_root" &&
   "$host_unit" == disk-arcana-stage-vm.service && "$runner_name" == disk-arcana-stage ]] ||
  die 65 'state manifest identity mismatch'
[[ "$management_port" =~ ^[0-9]+$ && "$cloud_image_sha256" =~ ^[0-9a-f]{64}$ &&
   "$guest_bundle_sha256" =~ ^[0-9a-f]{64}$ &&
   "$runner_archive_sha256" =~ ^[0-9a-f]{64}$ ]] || die 65 'state manifest metadata is invalid'
[[ "$manifest_runner_id" == UNREGISTERED || "$manifest_runner_id" == "$requested_runner_id" ]] ||
  die 66 'state manifest is bound to another runner ID'

github_token="$(<"$github_token_file")"
[[ "$github_token" =~ ^[^[:space:]]{20,500}$ ]] || die 65 'GitHub token is malformed'
command -v jq >/dev/null 2>&1 || die 69 'jq is unavailable'
if [[ "$test_mode" == true ]]; then
  api_response_file="$DISK_ARCANA_STAGE_BIND_API_RESPONSE"
  [[ -f "$api_response_file" && ! -L "$api_response_file" ]] ||
    die 65 'API response fixture is unsafe'
  api_response="$(<"$api_response_file")"
  group_api_response_file="$DISK_ARCANA_STAGE_BIND_GROUP_API_RESPONSE"
  [[ -f "$group_api_response_file" && ! -L "$group_api_response_file" ]] ||
    die 65 'group API response fixture is unsafe'
  group_api_response="$(<"$group_api_response_file")"
else
  command -v curl >/dev/null 2>&1 || die 69 'curl is unavailable'
  api_response="$(
    curl --fail --silent --show-error --max-time 20 \
      -H "Authorization: Bearer $github_token" \
      -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' \
      "https://api.github.com/orgs/Arcanada-one/actions/runners/$requested_runner_id"
  )" || die 69 'GitHub runner readback failed'
  group_api_response="$(
    curl --fail --silent --show-error --max-time 20 \
      -H "Authorization: Bearer $github_token" \
      -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' \
      'https://api.github.com/orgs/Arcanada-one/actions/runner-groups/8/runners?per_page=100'
  )" || die 69 'GitHub runner group readback failed'
fi
api_id="$(jq -er '.id | select(type == "number")' <<<"$api_response")" ||
  die 66 'GitHub runner readback is malformed'
api_name="$(jq -er '.name | select(type == "string")' <<<"$api_response")" ||
  die 66 'GitHub runner readback is malformed'
[[ "$api_id" == "$requested_runner_id" && "$api_name" == "$runner_name" ]] ||
  die 66 'GitHub runner identity mismatch'
api_status="$(jq -er '.status | select(type == "string")' <<<"$api_response")" ||
  die 66 'GitHub runner readback is malformed'
api_busy="$(jq -r 'if (.busy | type) == "boolean" then (.busy | tostring) else error("busy") end' \
  <<<"$api_response")" ||
  die 66 'GitHub runner readback is malformed'
api_has_label="$(jq -r 'if (.labels | type) == "array" then ([.labels[]?.name] | index("disk-arcana-stage") != null | tostring) else error("labels") end' \
  <<<"$api_response")" || die 66 'GitHub runner readback is malformed'
group_match_count="$(jq -er --argjson id "$requested_runner_id" --arg name "$runner_name" \
  '[.runners[]? | select(.id == $id and .name == $name)] | length' \
  <<<"$group_api_response")" || die 66 'GitHub runner group readback is malformed'
[[ "$api_status" == online && "$api_busy" == false && "$api_has_label" == true &&
   "$group_match_count" == 1 ]] || die 66 'GitHub runner boundary mismatch'

if [[ "$validate_only" == true ]]; then
  printf 'validation=ok runner_id=%s runner_name=%s\n' "$requested_runner_id" "$runner_name"
  exit 0
fi
if [[ "$manifest_runner_id" == "$requested_runner_id" ]]; then
  printf 'binding=already-committed runner_id=%s runner_name=%s\n' "$requested_runner_id" "$runner_name"
  exit 0
fi

temporary="$state_root/.state.manifest.$$"
{
  printf 'guest_name=%s\n' "$guest_name"
  printf 'state_root=%s\n' "$manifest_state_root"
  printf 'host_unit=%s\n' "$host_unit"
  printf 'management_port=%s\n' "$management_port"
  printf 'cloud_image_sha256=%s\n' "$cloud_image_sha256"
  printf 'guest_bundle_sha256=%s\n' "$guest_bundle_sha256"
  printf 'runner_archive_sha256=%s\n' "$runner_archive_sha256"
  printf 'runner_name=%s\n' "$runner_name"
  printf 'runner_id=%s\n' "$requested_runner_id"
} >"$temporary"
chmod 0600 "$temporary"
sync -f "$temporary" >/dev/null 2>&1
mv -f -- "$temporary" "$manifest"
sync -f "$state_root" >/dev/null 2>&1
printf 'binding=committed runner_id=%s runner_name=%s\n' "$requested_runner_id" "$runner_name"
