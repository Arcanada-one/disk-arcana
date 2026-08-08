#!/usr/bin/env bash
# INFRA-0370: crash-recoverable deployment of the Disk Arcana server binary
# and systemd unit. This is the only release-update state machine; the broker
# supplies a validated, root-owned inbox and this helper owns activation,
# verification, rollback, and next-invocation recovery.

set -euo pipefail
IFS=$'\n\t'
umask 077

readonly UNIT_NAME="disk-arcana-server.service"
readonly SERVICE_NAME="disk-arcana-server"
readonly HEALTH_URL="http://127.0.0.1:9446/health"
readonly EXPECT_INTERVAL="2min"
readonly EXPECT_BURST="5"
readonly MANIFEST_NAME="manifest.sha256"
readonly -a REQUIRED_MEMBERS=(
  commit
  deploy-server-broker.sh
  deploy-server.sh
  disk-arcana-deploy.sudoers
  disk-arcana-server
  disk-arcana-server.service
  provision-deploy-broker.sh
)

TEST_MODE=0
ROOT=""
BUNDLE=""
EXPECTED_COMMIT=""
EXPECTED_HOSTNAME=""
TX_STATE=""
TX_BACKUP=""
TX_OLD_BINARY_SHA=""
TX_OLD_UNIT_SHA=""
TX_NEW_BINARY_SHA=""
TX_NEW_UNIT_SHA=""
TX_COMMIT=""
TX_STAGE_BINARY=""
TX_STAGE_UNIT=""

usage() {
  printf 'usage: %s --bundle DIR --expected-commit SHA --expected-hostname HOST\n' \
    "$(basename "$0")" >&2
  exit 2
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

safe_error() {
  # Callers pass only fixed messages. Never forward child stderr: unit files,
  # health bodies, and command environments may carry secret-adjacent data.
  printf 'ERROR: %s\n' "$1" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle)
      [[ $# -ge 2 ]] || usage
      BUNDLE="$2"
      shift 2
      ;;
    --expected-commit)
      [[ $# -ge 2 ]] || usage
      EXPECTED_COMMIT="$2"
      shift 2
      ;;
    --expected-hostname)
      [[ $# -ge 2 ]] || usage
      EXPECTED_HOSTNAME="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "$BUNDLE" && -n "$EXPECTED_COMMIT" && -n "$EXPECTED_HOSTNAME" ]] || usage
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "expected commit must be 40 lowercase hexadecimal characters"
[[ "$EXPECTED_HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || die "invalid expected hostname"

if [[ "${DISK_ARCANA_DEPLOY_TESTING:-}" == 1 ]]; then
  [[ "$(id -u)" -ne 0 ]] || die "test mode is forbidden for root invocations"
  [[ -n "${DISK_ARCANA_DEPLOY_TEST_ROOT:-}" ]] || die "test mode requires a fake root"
  TEST_MODE=1
  ROOT="${DISK_ARCANA_DEPLOY_TEST_ROOT%/}"
  [[ "$ROOT" == /* && "$ROOT" != / && -d "$ROOT" && ! -L "$ROOT" ]] || die "unsafe test root"
else
  [[ "$(id -u)" -eq 0 ]] || die "production deployment requires root"
  [[ -z "${DISK_ARCANA_DEPLOY_TEST_ROOT:-}" ]] || die "test root is forbidden in production mode"
  [[ -z "${DISK_ARCANA_DEPLOY_TEST_FAIL_AT:-}" ]] || die "test failure controls are forbidden in production mode"
  [[ -z "${DISK_ARCANA_DEPLOY_TEST_KILL_AFTER_STATE:-}" ]] || die "test crash controls are forbidden in production mode"
  [[ -z "${DISK_ARCANA_DEPLOY_TEST_KILL_AFTER_BINARY_ACTIVATION:-}" ]] || die "test split-activation control is forbidden in production mode"
fi

readonly LIVE_BINARY="$ROOT/usr/local/bin/disk-arcana-server"
readonly LIVE_UNIT="$ROOT/etc/systemd/system/$UNIT_NAME"
readonly STATE_ROOT="$ROOT/var/lib/disk-arcana/deploy-transactions"
readonly BACKUP_ROOT="$ROOT/var/lib/disk-arcana/deploy-backups"
readonly CURRENT_JOURNAL="$STATE_ROOT/current"
readonly RECORD_ROOT="$STATE_ROOT/records"
readonly LOCK_FILE="$ROOT/run/lock/disk-arcana-deploy.lock"

if (( TEST_MODE )); then
  EXPECT_UID="$(id -u)"
  EXPECT_GID="$(id -g)"
  HEALTH_ATTEMPTS=2
  HEALTH_DELAY=0
else
  EXPECT_UID=0
  EXPECT_GID=0
  HEALTH_ATTEMPTS=12
  HEALTH_DELAY=5
fi
readonly EXPECT_UID EXPECT_GID HEALTH_ATTEMPTS HEALTH_DELAY

install -d -m 0700 "$STATE_ROOT" "$BACKUP_ROOT" "$RECORD_ROOT"
install -d -m 0755 "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
flock -n 9 || die "another deployment holds the lock"

sha256_file() {
  sha256sum -- "$1" | awk '{print $1}'
}

fsync_path() {
  local path="$1"
  sync -f "$path" >/dev/null 2>&1 || return 1
}

mode_of() {
  stat -c '%a' -- "$1"
}

uid_of() {
  stat -c '%u' -- "$1"
}

gid_of() {
  stat -c '%g' -- "$1"
}

assert_regular_nonsymlink() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]]
}

assert_safe_destination() {
  local path="$1" expected_parent="$2"
  local actual_parent
  [[ ! -L "$path" ]] || return 1
  assert_regular_nonsymlink "$path" || return 1
  [[ ! -L "$expected_parent" && -d "$expected_parent" ]] || return 1
  actual_parent="$(realpath -e -- "$(dirname "$path")")" || return 1
  [[ "$actual_parent" == "$(realpath -e -- "$expected_parent")" ]]
}

manifest_digest() {
  local member="$1"
  awk -v wanted="$member" '$2 == wanted {print $1; found=1} END {if (!found) exit 1}' \
    "$BUNDLE/$MANIFEST_NAME"
}

validate_bundle() {
  local path member line_count=0 expected digest actual marker status=0 count i
  local -a inventory=()

  [[ "$BUNDLE" == /* && -d "$BUNDLE" && ! -L "$BUNDLE" ]] || return 1
  marker="__disk_arcana_inventory_success__"
  mapfile -d '' -t inventory < <(
    find "$BUNDLE" -mindepth 1 -maxdepth 1 -print0 || status=$?
    (( status == 0 )) && printf '%s\0' "$marker"
  )
  count=${#inventory[@]}
  (( count > 0 )) || return 1
  [[ "${inventory[$((count - 1))]}" == "$marker" ]] || return 1
  [[ "$count" -eq $((${#REQUIRED_MEMBERS[@]} + 2)) ]] || return 1

  for ((i = 0; i < count - 1; i++)); do
    path="${inventory[i]}"
    member="${path##*/}"
    if [[ "$member" != "$MANIFEST_NAME" ]]; then
      local allowed=0 required
      for required in "${REQUIRED_MEMBERS[@]}"; do
        [[ "$member" == "$required" ]] && allowed=1
      done
      (( allowed == 1 )) || return 1
    fi
    assert_regular_nonsymlink "$path" || return 1
  done

  awk -v expected="$EXPECTED_COMMIT" 'NR == 1 {value=$0} NR > 1 {extra=1}
    END {exit !(NR == 1 && !extra && value == expected)}' "$BUNDLE/commit" || return 1
  [[ "$(sha256_file "$BUNDLE/deploy-server.sh")" == "$(sha256_file "$0")" ]] || return 1

  while IFS= read -r line || [[ -n "$line" ]]; do
    line_count=$((line_count + 1))
    [[ "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([^[:space:]]+)$ ]] || return 1
    digest="${BASH_REMATCH[1]}"
    member="${BASH_REMATCH[2]}"
    (( line_count <= ${#REQUIRED_MEMBERS[@]} )) || return 1
    expected="${REQUIRED_MEMBERS[$((line_count - 1))]}"
    [[ "$member" == "$expected" ]] || return 1
    actual="$(sha256_file "$BUNDLE/$member")"
    [[ "$actual" == "$digest" ]] || return 1
  done <"$BUNDLE/$MANIFEST_NAME"
  [[ "$line_count" -eq "${#REQUIRED_MEMBERS[@]}" ]]
}

validate_unit_contract() {
  local unit="$1" key section="" count_interval=0 count_burst=0
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
  done <"$unit"
  [[ "$count_interval" -eq 1 && "$count_burst" -eq 1 ]] || return 1
  grep -qxF 'ExecStart=/usr/local/bin/disk-arcana-server' "$unit" || return 1
  grep -qxF 'User=disk-arcana' "$unit" || return 1
  grep -qxF 'Group=disk-arcana' "$unit" || return 1
  grep -qxF 'NoNewPrivileges=true' "$unit" || return 1
  grep -qxF 'ProtectSystem=strict' "$unit" || return 1
}

health_ok() {
  local body compact
  for _ in $(seq 1 "$HEALTH_ATTEMPTS"); do
    if body="$(curl --fail --silent --show-error --max-time 10 "$HEALTH_URL" 2>/dev/null)"; then
      compact="$(printf '%s' "$body" | tr -d '[:space:]')"
      if [[ "$compact" == *'"status":"ok"'* ]]; then
        return 0
      fi
    fi
    (( HEALTH_DELAY == 0 )) || sleep "$HEALTH_DELAY"
  done
  return 1
}

loaded_policy_ok() {
  local interval burst restart
  interval="$(systemctl show "$SERVICE_NAME" -p StartLimitIntervalUSec --value 2>/dev/null)" || return 1
  burst="$(systemctl show "$SERVICE_NAME" -p StartLimitBurst --value 2>/dev/null)" || return 1
  restart="$(systemctl show "$SERVICE_NAME" -p Restart --value 2>/dev/null)" || return 1
  [[ "$interval" == "$EXPECT_INTERVAL" && "$burst" == "$EXPECT_BURST" && "$restart" == on-failure ]]
}

journal_get() {
  local key="$1"
  awk -F= -v wanted="$key" '
    $1 == wanted {sub(/^[^=]*=/, ""); print; found=1}
    END {if (!found) exit 1}
  ' "$CURRENT_JOURNAL"
}

write_journal() {
  local tmp="$STATE_ROOT/.current.$$"
  {
    printf 'state=%s\n' "$TX_STATE"
    printf 'commit=%s\n' "$TX_COMMIT"
    printf 'backup=%s\n' "$TX_BACKUP"
    printf 'old_binary_sha=%s\n' "$TX_OLD_BINARY_SHA"
    printf 'old_unit_sha=%s\n' "$TX_OLD_UNIT_SHA"
    printf 'new_binary_sha=%s\n' "$TX_NEW_BINARY_SHA"
    printf 'new_unit_sha=%s\n' "$TX_NEW_UNIT_SHA"
    printf 'stage_binary=%s\n' "$TX_STAGE_BINARY"
    printf 'stage_unit=%s\n' "$TX_STAGE_UNIT"
    printf 'timestamp=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$tmp"
  chmod 0600 "$tmp"
  fsync_path "$tmp" || return 1
  mv -f -- "$tmp" "$CURRENT_JOURNAL"
  fsync_path "$STATE_ROOT" || return 1
}

maybe_inject_after_state() {
  if (( TEST_MODE )) && [[ "${DISK_ARCANA_DEPLOY_TEST_KILL_AFTER_STATE:-}" == "$TX_STATE" ]]; then
    kill -KILL "$$"
  fi
}

transition() {
  TX_STATE="$1"
  write_journal || return 1
  maybe_inject_after_state
}

archive_journal() {
  local suffix="$1" record
  record="$RECORD_ROOT/$(date -u +%Y%m%dT%H%M%SZ)-$$-$suffix"
  mv -f -- "$CURRENT_JOURNAL" "$record"
  fsync_path "$RECORD_ROOT" || return 1
  fsync_path "$STATE_ROOT" || return 1
}

restore_one() {
  local backup="$1" target="$2" tmp
  tmp="$(dirname "$target")/.${target##*/}.recover.$$"
  cp -a -- "$backup" "$tmp" || return 1
  fsync_path "$tmp" || return 1
  mv -f -- "$tmp" "$target" || return 1
  fsync_path "$(dirname "$target")" || return 1
}

cleanup_stages() {
  [[ "$(dirname "$TX_STAGE_BINARY")" == "$(dirname "$LIVE_BINARY")" ]] || return 1
  [[ "${TX_STAGE_BINARY##*/}" =~ ^\.disk-arcana-server\.stage\.[0-9]+$ ]] || return 1
  [[ "$(dirname "$TX_STAGE_UNIT")" == "$(dirname "$LIVE_UNIT")" ]] || return 1
  [[ "${TX_STAGE_UNIT##*/}" =~ ^\.disk-arcana-server\.service\.stage\.[0-9]+$ ]] || return 1
  rm -f -- "$TX_STAGE_BINARY" "$TX_STAGE_UNIT"
  fsync_path "$(dirname "$LIVE_BINARY")" || return 1
  fsync_path "$(dirname "$LIVE_UNIT")"
}

recover_current() {
  local prior_state backup expected_prefix
  [[ -f "$CURRENT_JOURNAL" && ! -L "$CURRENT_JOURNAL" ]] || return 0
  prior_state="$(journal_get state)" || return 1
  TX_COMMIT="$(journal_get commit)" || return 1
  [[ "$TX_COMMIT" =~ ^[0-9a-f]{40}$ ]] || return 1
  backup="$(journal_get backup)" || return 1
  TX_BACKUP="$backup"
  TX_OLD_BINARY_SHA="$(journal_get old_binary_sha)" || return 1
  TX_OLD_UNIT_SHA="$(journal_get old_unit_sha)" || return 1
  TX_NEW_BINARY_SHA="$(journal_get new_binary_sha)" || return 1
  TX_NEW_UNIT_SHA="$(journal_get new_unit_sha)" || return 1
  TX_STAGE_BINARY="$(journal_get stage_binary)" || return 1
  TX_STAGE_UNIT="$(journal_get stage_unit)" || return 1
  expected_prefix="$(realpath -e -- "$BACKUP_ROOT")/"
  [[ -d "$backup" && ! -L "$backup" ]] || return 1
  [[ "$(realpath -e -- "$backup")/" == "$expected_prefix"* ]] || return 1
  assert_regular_nonsymlink "$backup/disk-arcana-server" || return 1
  assert_regular_nonsymlink "$backup/$UNIT_NAME" || return 1
  [[ "$(sha256_file "$backup/disk-arcana-server")" == "$TX_OLD_BINARY_SHA" ]] || return 1
  [[ "$(sha256_file "$backup/$UNIT_NAME")" == "$TX_OLD_UNIT_SHA" ]] || return 1

  if [[ "$prior_state" == COMMITTED ]]; then
    [[ "$(sha256_file "$LIVE_BINARY")" == "$TX_NEW_BINARY_SHA" ]] || return 1
    [[ "$(sha256_file "$LIVE_UNIT")" == "$TX_NEW_UNIT_SHA" ]] || return 1
    systemctl is-active --quiet "$SERVICE_NAME" >/dev/null 2>&1 || return 1
    loaded_policy_ok || return 1
    health_ok || return 1
    cleanup_stages || return 1
    printf 'state=COMMITTED recovered_from=COMMITTED commit=%s\n' "$TX_COMMIT"
    archive_journal committed-recovered || return 1
    return 0
  fi

  if ! cleanup_stages ||
    ! restore_one "$backup/disk-arcana-server" "$LIVE_BINARY" ||
    ! restore_one "$backup/$UNIT_NAME" "$LIVE_UNIT" ||
    ! systemctl daemon-reload >/dev/null 2>&1 ||
    ! systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 ||
    ! systemctl is-active --quiet "$SERVICE_NAME" >/dev/null 2>&1 ||
    ! health_ok; then
    TX_STATE="FAILED_RECOVERY_REQUIRED"
    write_journal || true
    printf 'state=FAILED_RECOVERY_REQUIRED\n' >&2
    return 1
  fi

  [[ "$(sha256_file "$LIVE_BINARY")" == "$TX_OLD_BINARY_SHA" ]] || return 1
  [[ "$(sha256_file "$LIVE_UNIT")" == "$TX_OLD_UNIT_SHA" ]] || return 1
  TX_STATE="FAILED_RECOVERED"
  write_journal || return 1
  printf 'state=FAILED_RECOVERED recovered_from=%s\n' "$prior_state"
  archive_journal recovered || return 1
}

post_backup_failure() {
  safe_error "$1"
  if ! recover_current; then
    return 1
  fi
  return 1
}

recover_current || die "unfinished deployment could not be recovered"

TX_COMMIT="$EXPECTED_COMMIT"

actual_hostname="$(hostname 2>/dev/null)" || die "could not read hostname"
[[ "$actual_hostname" == "$EXPECTED_HOSTNAME" ]] || die "hostname mismatch"
validate_bundle || die "bundle validation failed"
validate_unit_contract "$BUNDLE/$UNIT_NAME" || die "unit contract validation failed"
systemd-analyze verify "$BUNDLE/$UNIT_NAME" >/dev/null 2>&1 || die "staged unit failed systemd verification"

assert_safe_destination "$LIVE_BINARY" "$ROOT/usr/local/bin" || die "unsafe existing binary destination"
assert_safe_destination "$LIVE_UNIT" "$ROOT/etc/systemd/system" || die "unsafe existing unit destination"
[[ "$(mode_of "$LIVE_BINARY")" == 755 && "$(mode_of "$LIVE_UNIT")" == 644 ]] || die "unexpected current file mode"
[[ "$(uid_of "$LIVE_BINARY")" == "$EXPECT_UID" && "$(gid_of "$LIVE_BINARY")" == "$EXPECT_GID" ]] || die "unexpected current binary ownership"
[[ "$(uid_of "$LIVE_UNIT")" == "$EXPECT_UID" && "$(gid_of "$LIVE_UNIT")" == "$EXPECT_GID" ]] || die "unexpected current unit ownership"
systemctl is-active --quiet "$SERVICE_NAME" >/dev/null 2>&1 || die "service is not active before deployment"
health_ok || die "service health baseline failed"

TX_NEW_BINARY_SHA="$(manifest_digest disk-arcana-server)" || die "binary missing from manifest"
TX_NEW_UNIT_SHA="$(manifest_digest "$UNIT_NAME")" || die "unit missing from manifest"

if [[ "$(sha256_file "$LIVE_BINARY")" == "$TX_NEW_BINARY_SHA" &&
  "$(sha256_file "$LIVE_UNIT")" == "$TX_NEW_UNIT_SHA" ]]; then
  loaded_policy_ok || die "installed policy does not match expected values"
  health_ok || die "installed service is unhealthy"
  printf 'state=COMMITTED idempotent=true commit=%s binary_sha=%s unit_sha=%s\n' \
    "$EXPECTED_COMMIT" "$TX_NEW_BINARY_SHA" "$TX_NEW_UNIT_SHA"
  exit 0
fi

TX_BACKUP="$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%SZ)-$$"
TX_STAGE_BINARY="$(dirname "$LIVE_BINARY")/.disk-arcana-server.stage.$$"
TX_STAGE_UNIT="$(dirname "$LIVE_UNIT")/.$UNIT_NAME.stage.$$"
install -d -m 0700 "$TX_BACKUP" || die "could not create protected backup"
cp -a -- "$LIVE_BINARY" "$TX_BACKUP/disk-arcana-server" || die "could not back up binary"
cp -a -- "$LIVE_UNIT" "$TX_BACKUP/$UNIT_NAME" || die "could not back up unit"
TX_OLD_BINARY_SHA="$(sha256_file "$TX_BACKUP/disk-arcana-server")"
TX_OLD_UNIT_SHA="$(sha256_file "$TX_BACKUP/$UNIT_NAME")"
fsync_path "$TX_BACKUP/disk-arcana-server" || die "could not fsync binary backup"
fsync_path "$TX_BACKUP/$UNIT_NAME" || die "could not fsync unit backup"
fsync_path "$TX_BACKUP" || die "could not fsync backup directory"
fsync_path "$BACKUP_ROOT" || die "could not fsync backup root"
transition BACKUP_WRITTEN || die "could not persist backup transaction"

if ! install -o "$EXPECT_UID" -g "$EXPECT_GID" -m 0755 "$BUNDLE/disk-arcana-server" "$TX_STAGE_BINARY" ||
  ! install -o "$EXPECT_UID" -g "$EXPECT_GID" -m 0644 "$BUNDLE/$UNIT_NAME" "$TX_STAGE_UNIT" ||
  ! fsync_path "$TX_STAGE_BINARY" ||
  ! fsync_path "$TX_STAGE_UNIT" ||
  ! systemd-analyze verify "$TX_STAGE_UNIT" >/dev/null 2>&1; then
  rm -f -- "$TX_STAGE_BINARY" "$TX_STAGE_UNIT"
  post_backup_failure "file staging failed"
  exit 1
fi
transition FILES_STAGED || {
  post_backup_failure "could not persist staged state"
  exit 1
}

if (( TEST_MODE )) && [[ "${DISK_ARCANA_DEPLOY_TEST_FAIL_AT:-}" == binary-activation ]]; then
  post_backup_failure "binary activation failed"
  exit 1
fi
if ! mv -f -- "$TX_STAGE_BINARY" "$LIVE_BINARY" || ! fsync_path "$(dirname "$LIVE_BINARY")"; then
  post_backup_failure "binary activation failed"
  exit 1
fi
if (( TEST_MODE )) && [[ "${DISK_ARCANA_DEPLOY_TEST_KILL_AFTER_BINARY_ACTIVATION:-}" == 1 ]]; then
  kill -KILL "$$"
fi
if (( TEST_MODE )) && [[ "${DISK_ARCANA_DEPLOY_TEST_FAIL_AT:-}" == unit-activation ]]; then
  post_backup_failure "unit activation failed"
  exit 1
fi
if ! mv -f -- "$TX_STAGE_UNIT" "$LIVE_UNIT" || ! fsync_path "$(dirname "$LIVE_UNIT")"; then
  post_backup_failure "unit activation failed"
  exit 1
fi
transition FILES_ACTIVATED || {
  post_backup_failure "could not persist activated state"
  exit 1
}

if ! systemctl daemon-reload >/dev/null 2>&1; then
  post_backup_failure "daemon reload failed"
  exit 1
fi
transition DAEMON_RELOADED || {
  post_backup_failure "could not persist daemon-reloaded state"
  exit 1
}

if ! systemctl restart "$SERVICE_NAME" >/dev/null 2>&1; then
  post_backup_failure "service restart failed"
  exit 1
fi
transition SERVICE_RESTARTED || {
  post_backup_failure "could not persist restarted state"
  exit 1
}

if ! systemctl is-active --quiet "$SERVICE_NAME" >/dev/null 2>&1 ||
  ! health_ok || ! loaded_policy_ok; then
  post_backup_failure "post-deploy verification failed"
  exit 1
fi
[[ "$(sha256_file "$LIVE_BINARY")" == "$TX_NEW_BINARY_SHA" ]] || {
  post_backup_failure "installed binary hash mismatch"
  exit 1
}
[[ "$(sha256_file "$LIVE_UNIT")" == "$TX_NEW_UNIT_SHA" ]] || {
  post_backup_failure "installed unit hash mismatch"
  exit 1
}
transition HEALTH_VERIFIED || {
  post_backup_failure "could not persist health-verified state"
  exit 1
}
transition COMMITTED || {
  post_backup_failure "could not persist committed state"
  exit 1
}
printf 'state=COMMITTED commit=%s binary_sha=%s unit_sha=%s\n' \
  "$EXPECTED_COMMIT" "$TX_NEW_BINARY_SHA" "$TX_NEW_UNIT_SHA"
archive_journal committed || die "could not archive committed transaction"
