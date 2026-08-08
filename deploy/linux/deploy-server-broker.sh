#!/usr/bin/env bash
# INFRA-0370: fixed privileged boundary for importing a runner-owned release
# bundle into a root-owned inbox and invoking the installed deployment helper.

set -euo pipefail
IFS=$'\n\t'
umask 077

readonly -a MEMBERS=(
  commit
  deploy-server-broker.sh
  deploy-server.sh
  disk-arcana-deploy.sudoers
  disk-arcana-server
  disk-arcana-server.service
  install.sh
  provision-deploy-broker.sh
)

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

[[ "${1:-}" == --deploy && $# -eq 3 ]] ||
  die "usage: $(basename "$0") --deploy BUNDLE AUTHORIZATION_ID"
readonly SOURCE_BUNDLE="$2"
readonly AUTHORIZATION_ID="$3"

TEST_MODE=0
ROOT=""
if [[ "${DISK_ARCANA_BROKER_TESTING:-}" == 1 ]]; then
  [[ "$(id -u)" -ne 0 ]] || die "test mode is forbidden for root invocations"
  [[ -n "${DISK_ARCANA_BROKER_TEST_ROOT:-}" ]] || die "test mode requires a fake root"
  TEST_MODE=1
  ROOT="${DISK_ARCANA_BROKER_TEST_ROOT%/}"
  [[ "$ROOT" == /* && "$ROOT" != / && -d "$ROOT" && ! -L "$ROOT" ]] || die "unsafe test root"
  CALLER="${DISK_ARCANA_BROKER_TEST_CALLER:-}"
else
  [[ "$(id -u)" -eq 0 ]] || die "broker requires root"
  [[ -z "${DISK_ARCANA_BROKER_TEST_ROOT:-}" ]] || die "test root is forbidden in production"
  [[ -z "${DISK_ARCANA_BROKER_TEST_CALLER:-}" ]] || die "test caller is forbidden in production"
  [[ -z "${DISK_ARCANA_BROKER_TEST_HELPER_LOG:-}" ]] || die "test helper is forbidden in production"
  CALLER="${SUDO_USER:-}"
fi

if (( TEST_MODE )); then
  EXPECT_UID="$(id -u)"
  EXPECT_GID="$(id -g)"
else
  EXPECT_UID=0
  EXPECT_GID=0
fi
readonly EXPECT_UID EXPECT_GID

readonly CONFIG="$ROOT/etc/disk-arcana/deploy.conf"
readonly DEPLOY_ROOT="$ROOT/var/lib/disk-arcana-deploy"
readonly INBOX_ROOT="$DEPLOY_ROOT/inbox"
readonly AUTHORIZATION_ROOT="$DEPLOY_ROOT/authorizations"
readonly CONSUMED_AUTHORIZATION_ROOT="$AUTHORIZATION_ROOT/consumed"
readonly INSTALLED_HELPER="$ROOT/usr/local/libexec/disk-arcana/deploy-server.sh"
readonly INSTALLED_BROKER="$ROOT/usr/local/sbin/disk-arcana-deploy-broker"
readonly EXPECTED_REPOSITORY="Arcanada-one/disk-arcana"
readonly EXPECTED_WORKFLOW_REF="Arcanada-one/disk-arcana/.github/workflows/release-deploy.yml@refs/heads/main"

assert_no_symlink_components() {
  local path="$1" relative current component
  local -a components=()
  [[ "$path" == /* ]] || return 1
  if [[ -n "$ROOT" ]]; then
    [[ "$path" == "$ROOT" || "$path" == "$ROOT"/* ]] || return 1
    relative="${path#"$ROOT"}"; relative="${relative#/}"; current="$ROOT"
  else
    relative="${path#/}"; current=""
  fi
  IFS=/ read -r -a components <<<"$relative"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || return 1
    current="$current/$component"
    [[ ! -L "$current" ]] || return 1
  done
}

for fixed_path in "$CONFIG" "$INBOX_ROOT" "$AUTHORIZATION_ROOT" \
  "$CONSUMED_AUTHORIZATION_ROOT" "$INSTALLED_HELPER" "$INSTALLED_BROKER"; do
  assert_no_symlink_components "$fixed_path" || die "broker path has a symlink component"
done

[[ "$AUTHORIZATION_ID" =~ ^[0-9]{1,20}-[0-9]{1,10}-(staging|production)$ ]] ||
  die "invalid deployment authorization id"
[[ -f "$CONFIG" && ! -L "$CONFIG" && "$(stat -c '%a' "$CONFIG")" == 600 ]] || die "unsafe broker config"
[[ -f "$INSTALLED_HELPER" && ! -L "$INSTALLED_HELPER" && "$(stat -c '%a' "$INSTALLED_HELPER")" == 755 ]] || die "unsafe installed helper"
[[ -f "$INSTALLED_BROKER" && ! -L "$INSTALLED_BROKER" && "$(stat -c '%a' "$INSTALLED_BROKER")" == 755 ]] || die "unsafe installed broker"
[[ "$(stat -c '%u' "$CONFIG")" == "$EXPECT_UID" && "$(stat -c '%g' "$CONFIG")" == "$EXPECT_GID" ]] || die "unsafe broker config ownership"
[[ "$(stat -c '%u' "$INSTALLED_HELPER")" == "$EXPECT_UID" && "$(stat -c '%g' "$INSTALLED_HELPER")" == "$EXPECT_GID" ]] || die "unsafe helper ownership"
[[ "$(stat -c '%u' "$INSTALLED_BROKER")" == "$EXPECT_UID" && "$(stat -c '%g' "$INSTALLED_BROKER")" == "$EXPECT_GID" ]] || die "unsafe broker ownership"

RUNNER_USER=""
RUNNER_GROUP=""
IMPORT_ROOT=""
CONFIG_HOST=""
declare -A CONFIG_SEEN=()
while IFS='=' read -r key value; do
  [[ -z "${CONFIG_SEEN[$key]+present}" ]] || die "duplicate broker config key"
  CONFIG_SEEN["$key"]=1
  case "$key" in
    runner_user) RUNNER_USER="$value" ;;
    runner_group) RUNNER_GROUP="$value" ;;
    import_root) IMPORT_ROOT="$value" ;;
    expected_hostname) CONFIG_HOST="$value" ;;
    *) die "unknown broker config key" ;;
  esac
done <"$CONFIG"

[[ "$RUNNER_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "invalid configured runner user"
[[ "$RUNNER_GROUP" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "invalid configured runner group"
[[ "$CALLER" == "$RUNNER_USER" && "$CALLER" != root ]] || die "caller is not the configured runner"
[[ "$IMPORT_ROOT" == /* && "$IMPORT_ROOT" != / && -d "$IMPORT_ROOT" && ! -L "$IMPORT_ROOT" ]] || die "unsafe import root"
[[ "$SOURCE_BUNDLE" == /* && -d "$SOURCE_BUNDLE" && ! -L "$SOURCE_BUNDLE" ]] || die "unsafe source bundle"

AUTHORIZATION_FILE="$AUTHORIZATION_ROOT/$AUTHORIZATION_ID.auth"
[[ -d "$AUTHORIZATION_ROOT" && ! -L "$AUTHORIZATION_ROOT" && "$(stat -c '%a:%u:%g' "$AUTHORIZATION_ROOT")" == "700:$EXPECT_UID:$EXPECT_GID" ]] ||
  die "unsafe authorization root"
[[ -d "$CONSUMED_AUTHORIZATION_ROOT" && ! -L "$CONSUMED_AUTHORIZATION_ROOT" && "$(stat -c '%a:%u:%g' "$CONSUMED_AUTHORIZATION_ROOT")" == "700:$EXPECT_UID:$EXPECT_GID" ]] ||
  die "unsafe consumed-authorization root"
[[ -f "$AUTHORIZATION_FILE" && ! -L "$AUTHORIZATION_FILE" && "$(stat -c '%a:%u:%g' "$AUTHORIZATION_FILE")" == "600:$EXPECT_UID:$EXPECT_GID" ]] ||
  die "deployment authorization is absent or unsafe"

AUTH_REPOSITORY="" AUTH_WORKFLOW_REF="" AUTH_RUN_ID="" AUTH_RUN_ATTEMPT=""
AUTH_TARGET="" AUTH_COMMIT="" AUTH_ARTIFACT_ID="" AUTH_ARTIFACT_DIGEST=""
AUTH_MANIFEST_SHA="" AUTH_HOSTNAME="" AUTH_NONCE="" AUTH_EXPIRES=""
declare -A AUTH_SEEN=()
while IFS='=' read -r key value; do
  [[ -z "${AUTH_SEEN[$key]+present}" ]] || die "duplicate deployment authorization key"
  AUTH_SEEN["$key"]=1
  case "$key" in
    repository) AUTH_REPOSITORY="$value" ;;
    workflow_ref) AUTH_WORKFLOW_REF="$value" ;;
    run_id) AUTH_RUN_ID="$value" ;;
    run_attempt) AUTH_RUN_ATTEMPT="$value" ;;
    target) AUTH_TARGET="$value" ;;
    commit) AUTH_COMMIT="$value" ;;
    artifact_id) AUTH_ARTIFACT_ID="$value" ;;
    artifact_digest) AUTH_ARTIFACT_DIGEST="$value" ;;
    manifest_sha) AUTH_MANIFEST_SHA="$value" ;;
    hostname) AUTH_HOSTNAME="$value" ;;
    nonce) AUTH_NONCE="$value" ;;
    expires) AUTH_EXPIRES="$value" ;;
    *) die "unknown deployment authorization key" ;;
  esac
done <"$AUTHORIZATION_FILE"

[[ "$AUTH_REPOSITORY" == "$EXPECTED_REPOSITORY" ]] || die "repository is not authorized"
[[ "$AUTH_WORKFLOW_REF" == "$EXPECTED_WORKFLOW_REF" ]] || die "workflow ref is not authorized"
[[ "$AUTH_RUN_ID" =~ ^[0-9]{1,20}$ && "$AUTH_RUN_ATTEMPT" =~ ^[0-9]{1,10}$ ]] || die "invalid authorized workflow run"
[[ "$AUTH_TARGET" =~ ^(staging|production)$ ]] || die "invalid authorized target"
[[ "$AUTHORIZATION_ID" == "$AUTH_RUN_ID-$AUTH_RUN_ATTEMPT-$AUTH_TARGET" ]] || die "authorization identity mismatch"
[[ "$AUTH_COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "invalid authorized commit"
[[ "$AUTH_ARTIFACT_ID" =~ ^[0-9]{1,20}$ ]] || die "invalid authorized artifact id"
[[ "$AUTH_ARTIFACT_DIGEST" =~ ^[0-9a-f]{64}$ ]] || die "invalid authorized artifact digest"
[[ "$AUTH_MANIFEST_SHA" =~ ^[0-9a-f]{64}$ ]] || die "invalid authorized manifest identity"
[[ "$AUTH_HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || die "invalid authorized hostname"
[[ "$AUTH_NONCE" =~ ^[A-Za-z0-9._-]{20,120}$ ]] || die "invalid authorization nonce"
[[ "$AUTH_EXPIRES" =~ ^[0-9]{10,12}$ && "$AUTH_EXPIRES" -gt "$(date +%s)" ]] || die "deployment authorization expired"
[[ "$CONFIG_HOST" == "$AUTH_HOSTNAME" ]] || die "destination hostname is not authorized"
[[ "$(hostname 2>/dev/null)" == "$AUTH_HOSTNAME" ]] || die "hostname mismatch"

readonly EXPECTED_COMMIT="$AUTH_COMMIT"
readonly EXPECTED_HOSTNAME="$AUTH_HOSTNAME"

canonical_import="$(realpath -e -- "$IMPORT_ROOT")" || die "could not resolve import root"
canonical_bundle="$(realpath -e -- "$SOURCE_BUNDLE")" || die "could not resolve source bundle"
[[ "$canonical_bundle" == "$canonical_import"/* ]] || die "bundle is outside the configured import root"
[[ "$(realpath -e -- "$(dirname "$SOURCE_BUNDLE")")" == "$canonical_import" ]] || die "bundle must be a direct child of import root"

sha() {
  sha256sum -- "$1" | awk '{print $1}'
}

is_member() {
  local wanted="$1" candidate
  for candidate in "${MEMBERS[@]}"; do
    [[ "$wanted" == "$candidate" ]] && return 0
  done
  return 1
}

validate_bundle() {
  local marker="__disk_arcana_inventory_success__" path member digest actual line=0 status=0
  local -a inventory=()
  mapfile -d '' -t inventory < <(
    find "$SOURCE_BUNDLE" -mindepth 1 -maxdepth 1 -print0 || status=$?
    (( status == 0 )) && printf '%s\0' "$marker"
  )
  [[ "${#inventory[@]}" -eq $((${#MEMBERS[@]} + 2)) ]] || return 1
  [[ "${inventory[$((${#inventory[@]} - 1))]}" == "$marker" ]] || return 1
  for path in "${inventory[@]:0:$((${#inventory[@]} - 1))}"; do
    member="${path##*/}"
    [[ "$member" == manifest.sha256 ]] || is_member "$member" || return 1
    [[ -f "$path" && ! -L "$path" ]] || return 1
  done
  awk -v expected="$EXPECTED_COMMIT" 'NR == 1 {value=$0} NR > 1 {extra=1}
    END {exit !(NR == 1 && !extra && value == expected)}' "$SOURCE_BUNDLE/commit" || return 1
  while IFS= read -r row || [[ -n "$row" ]]; do
    line=$((line + 1))
    [[ "$row" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([^[:space:]]+)$ ]] || return 1
    digest="${BASH_REMATCH[1]}"
    member="${BASH_REMATCH[2]}"
    (( line <= ${#MEMBERS[@]} )) || return 1
    [[ "$member" == "${MEMBERS[$((line - 1))]}" ]] || return 1
    actual="$(sha "$SOURCE_BUNDLE/$member")"
    [[ "$actual" == "$digest" ]] || return 1
  done <"$SOURCE_BUNDLE/manifest.sha256"
  [[ "$line" -eq "${#MEMBERS[@]}" ]] || return 1
  [[ "$(sha "$SOURCE_BUNDLE/deploy-server.sh")" == "$(sha "$INSTALLED_HELPER")" ]] || return 1
  [[ "$(sha "$SOURCE_BUNDLE/deploy-server-broker.sh")" == "$(sha "$INSTALLED_BROKER")" ]] || return 1
}

validate_unit_contract() {
  local section="" key line count_interval=0 count_burst=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^\[([^]]+)\]$ ]]; then
      section="${BASH_REMATCH[1]}"
      continue
    fi
    key="${line%%=*}"
    case "$key" in
      StartLimitIntervalSec)
        [[ "$section" == Unit && "$line" == StartLimitIntervalSec=120s ]] || return 1
        count_interval=$((count_interval + 1))
        ;;
      StartLimitBurst)
        [[ "$section" == Unit && "$line" == StartLimitBurst=5 ]] || return 1
        count_burst=$((count_burst + 1))
        ;;
    esac
  done <"$SOURCE_BUNDLE/disk-arcana-server.service"
  [[ "$count_interval" -eq 1 && "$count_burst" -eq 1 ]] || return 1
  grep -qxF 'ExecStart=/usr/local/bin/disk-arcana-server' "$SOURCE_BUNDLE/disk-arcana-server.service" || return 1
  grep -qxF 'User=disk-arcana' "$SOURCE_BUNDLE/disk-arcana-server.service" || return 1
  grep -qxF 'Group=disk-arcana' "$SOURCE_BUNDLE/disk-arcana-server.service" || return 1
  grep -qxF 'NoNewPrivileges=true' "$SOURCE_BUNDLE/disk-arcana-server.service" || return 1
  grep -qxF 'ProtectSystem=strict' "$SOURCE_BUNDLE/disk-arcana-server.service" || return 1
  systemd-analyze verify "$SOURCE_BUNDLE/disk-arcana-server.service" >/dev/null 2>&1
}

validate_bundle || die "bundle validation failed"
validate_unit_contract || die "unit contract validation failed"
[[ "$(sha "$SOURCE_BUNDLE/manifest.sha256")" == "$AUTH_MANIFEST_SHA" ]] ||
  die "bundle is not bound to the root authorization"

[[ -d "$INBOX_ROOT" && ! -L "$INBOX_ROOT" && "$(stat -c '%a' "$INBOX_ROOT")" == 700 ]] || die "unsafe inbox root"
[[ "$(stat -c '%u' "$INBOX_ROOT")" == "$EXPECT_UID" && "$(stat -c '%g' "$INBOX_ROOT")" == "$EXPECT_GID" ]] || die "unsafe inbox ownership"
consumed_authorization="$CONSUMED_AUTHORIZATION_ROOT/$AUTHORIZATION_ID-$AUTH_NONCE"
[[ ! -e "$consumed_authorization" ]] || die "deployment authorization was already consumed"
mv -- "$AUTHORIZATION_FILE" "$consumed_authorization" || die "could not consume deployment authorization"
sync -f "$consumed_authorization" >/dev/null 2>&1 || die "authorization consumption fsync failed"
sync -f "$AUTHORIZATION_ROOT" >/dev/null 2>&1 || die "authorization root fsync failed"
sync -f "$CONSUMED_AUTHORIZATION_ROOT" >/dev/null 2>&1 || die "consumed authorization root fsync failed"
inbox="$INBOX_ROOT/$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM"
install -d -m 0700 "$inbox" || die "could not create protected inbox"
for member in "${MEMBERS[@]}" manifest.sha256; do
  install -m 0600 "$SOURCE_BUNDLE/$member" "$inbox/$member" || die "bundle import failed"
  sync -f "$inbox/$member" >/dev/null 2>&1 || die "bundle import fsync failed"
done
sync -f "$inbox" >/dev/null 2>&1 || die "inbox fsync failed"
sync -f "$INBOX_ROOT" >/dev/null 2>&1 || die "inbox root fsync failed"

if (( TEST_MODE )); then
  [[ -n "${DISK_ARCANA_BROKER_TEST_HELPER_LOG:-}" ]] || die "test helper log is required"
  printf '%s\n' \
    "--bundle $inbox" \
    "--expected-commit $EXPECTED_COMMIT" \
    "--expected-hostname $EXPECTED_HOSTNAME" >"$DISK_ARCANA_BROKER_TEST_HELPER_LOG"
else
  "$INSTALLED_HELPER" --bundle "$inbox" \
    --expected-commit "$EXPECTED_COMMIT" \
    --expected-hostname "$EXPECTED_HOSTNAME"
fi
