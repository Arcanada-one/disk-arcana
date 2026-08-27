#!/usr/bin/env bash
# INFRA-0370: consume one root-issued authorization packet, install the fixed
# broker boundary atomically, and revoke the bootstrap authority path.

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
readonly -a TARGET_NAMES=(helper broker sudoers config lock legacy_broker legacy_sudoers)

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

[[ "${1:-}" == --bundle && "${3:-}" == --authorization && $# -eq 4 ]] ||
  die "usage: $(basename "$0") --bundle BUNDLE --authorization FILE"
BUNDLE="$2"
AUTH="$4"

TEST_MODE=0
ROOT=""
if [[ "${DISK_ARCANA_PROVISION_TESTING:-}" == 1 ]]; then
  [[ "$(id -u)" -ne 0 ]] || die "test mode is forbidden for root invocations"
  [[ -n "${DISK_ARCANA_PROVISION_TEST_ROOT:-}" ]] || die "test mode requires a fake root"
  TEST_MODE=1
  ROOT="${DISK_ARCANA_PROVISION_TEST_ROOT%/}"
  [[ "$ROOT" == /* && "$ROOT" != / && -d "$ROOT" && ! -L "$ROOT" ]] || die "unsafe test root"
else
  [[ "$(id -u)" -eq 0 ]] || die "provisioning requires root"
  [[ -z "${DISK_ARCANA_PROVISION_TEST_ROOT:-}" ]] || die "test root is forbidden in production"
  [[ -z "${DISK_ARCANA_PROVISION_TEST_FAIL_AT:-}" ]] || die "test failure control is forbidden in production"
  [[ -z "${DISK_ARCANA_PROVISION_TEST_KILL_AFTER_STATE:-}" ]] || die "test crash control is forbidden in production"
fi

readonly DEPLOY_ROOT="$ROOT/var/lib/disk-arcana-deploy"
readonly STATE_ROOT="$DEPLOY_ROOT/transactions"
readonly NONCE_ROOT="$STATE_ROOT/used-authorizations"
readonly RECORD_ROOT="$STATE_ROOT/provision-records"
readonly BACKUP_ROOT="$STATE_ROOT/provision-backups"
readonly JOURNAL="$STATE_ROOT/provision-current"
readonly HELPER_TARGET="$ROOT/usr/local/libexec/disk-arcana/deploy-server.sh"
readonly BROKER_TARGET="$ROOT/usr/local/sbin/disk-arcana-deploy-broker"
readonly SUDOERS_TARGET="$ROOT/etc/sudoers.d/disk-arcana-deploy"
readonly CONFIG_TARGET="$ROOT/etc/disk-arcana/deploy.conf"
readonly INBOX_ROOT="$DEPLOY_ROOT/inbox"
readonly AUTHORIZATION_ROOT="$DEPLOY_ROOT/authorizations"
readonly CONSUMED_AUTHORIZATION_ROOT="$AUTHORIZATION_ROOT/consumed"
readonly LOCK_TARGET="$ROOT/run/lock/disk-arcana-deploy.lock"
readonly LEGACY_BROKER_TARGET="$ROOT/usr/local/sbin/disk-arcana-install-unit"
readonly LEGACY_SUDOERS_TARGET="$ROOT/etc/sudoers.d/disk-arcana-install-unit"
readonly HELPER_BACKUP_ROOT="$DEPLOY_ROOT/backups"
readonly HELPER_RECORD_ROOT="$STATE_ROOT/records"
readonly -a TARGETS=(
  "$HELPER_TARGET"
  "$BROKER_TARGET"
  "$SUDOERS_TARGET"
  "$CONFIG_TARGET"
  "$LOCK_TARGET"
  "$LEGACY_BROKER_TARGET"
  "$LEGACY_SUDOERS_TARGET"
)
readonly -a DIRECTORY_NAMES=(helper_parent broker_parent sudoers_parent config_parent inbox authorizations consumed_authorizations helper_backups helper_records)
readonly -a DIRECTORY_PATHS=(
  "$(dirname "$HELPER_TARGET")"
  "$(dirname "$BROKER_TARGET")"
  "$(dirname "$SUDOERS_TARGET")"
  "$(dirname "$CONFIG_TARGET")"
  "$INBOX_ROOT"
  "$AUTHORIZATION_ROOT"
  "$CONSUMED_AUTHORIZATION_ROOT"
  "$HELPER_BACKUP_ROOT"
  "$HELPER_RECORD_ROOT"
)
readonly -a DIRECTORY_CREATE_MODES=(0755 0755 0755 0755 0700 0700 0700 0700 0700)

if (( TEST_MODE )); then
  EXPECT_UID="$(id -u)"
  EXPECT_GID="$(id -g)"
else
  EXPECT_UID=0
  EXPECT_GID=0
fi
readonly EXPECT_UID EXPECT_GID

fsync_path() {
  sync -f "$1" >/dev/null 2>&1
}

sha() {
  sha256sum -- "$1" | awk '{print $1}'
}

journal_get() {
  local key="$1"
  awk -F= -v wanted="$key" '
    $1 == wanted {sub(/^[^=]*=/, ""); print; found=1}
    END {if (!found) exit 1}
  ' "$JOURNAL"
}

TX_STATE=""
TX_BACKUP=""
TX_DEPLOYMENT=""
TX_COMMIT=""
TX_BOOTSTRAP=""
TX_HELPER_SHA=""
TX_BROKER_SHA=""
TX_SUDOERS_SHA=""
TX_CONFIG_SHA=""
TX_GROUP_EXISTED=""
TX_MEMBER_EXISTED=""
TX_RUNNER_USER=""
TX_NONCE=""
declare -a TX_DIRECTORY_EXISTED=()
declare -a TX_DIRECTORY_MODE=()
declare -a TX_DIRECTORY_UID=()
declare -a TX_DIRECTORY_GID=()

write_journal() {
  local tmp="$STATE_ROOT/.provision-current.$$" timestamp
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || return 1
  {
    printf 'state=%s\n' "$TX_STATE"
    printf 'deployment_id=%s\n' "$TX_DEPLOYMENT"
    printf 'commit=%s\n' "$TX_COMMIT"
    printf 'backup=%s\n' "$TX_BACKUP"
    printf 'bootstrap_root=%s\n' "$TX_BOOTSTRAP"
    printf 'helper_sha=%s\n' "$TX_HELPER_SHA"
    printf 'broker_sha=%s\n' "$TX_BROKER_SHA"
    printf 'sudoers_sha=%s\n' "$TX_SUDOERS_SHA"
    printf 'config_sha=%s\n' "$TX_CONFIG_SHA"
    printf 'group_existed=%s\n' "$TX_GROUP_EXISTED"
    printf 'member_existed=%s\n' "$TX_MEMBER_EXISTED"
    printf 'runner_user=%s\n' "$TX_RUNNER_USER"
    printf 'nonce=%s\n' "$TX_NONCE"
    local i
    for ((i = 0; i < ${#DIRECTORY_NAMES[@]}; i++)); do
      printf 'dir_%s_existed=%s\n' "${DIRECTORY_NAMES[i]}" "${TX_DIRECTORY_EXISTED[i]}"
      printf 'dir_%s_mode=%s\n' "${DIRECTORY_NAMES[i]}" "${TX_DIRECTORY_MODE[i]}"
      printf 'dir_%s_uid=%s\n' "${DIRECTORY_NAMES[i]}" "${TX_DIRECTORY_UID[i]}"
      printf 'dir_%s_gid=%s\n' "${DIRECTORY_NAMES[i]}" "${TX_DIRECTORY_GID[i]}"
    done
    printf 'timestamp=%s\n' "$timestamp"
  } >"$tmp" || return 1
  chmod 0600 "$tmp" || return 1
  fsync_path "$tmp" || return 1
  mv -f -- "$tmp" "$JOURNAL" || return 1
  fsync_path "$STATE_ROOT"
}

transition() {
  TX_STATE="$1"
  write_journal || return 1
  if (( TEST_MODE )) && [[ "${DISK_ARCANA_PROVISION_TEST_KILL_AFTER_STATE:-}" == "$TX_STATE" ]]; then
    kill -KILL "$$"
  fi
}

archive_journal() {
  local suffix="$1" record timestamp
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)" || return 1
  record="$RECORD_ROOT/$timestamp-$$-$suffix"
  mv -f -- "$JOURNAL" "$record" || return 1
  fsync_path "$RECORD_ROOT" || return 1
  fsync_path "$STATE_ROOT"
}

restore_targets() {
  local i name target backup tmp
  for ((i = 0; i < ${#TARGETS[@]}; i++)); do
    name="${TARGET_NAMES[i]}"
    target="${TARGETS[i]}"
    backup="$TX_BACKUP/$name"
    [[ ! -L "$target" ]] || return 1
    if [[ -f "$TX_BACKUP/$name.present" ]]; then
      [[ -f "$backup" && ! -L "$backup" ]] || return 1
      tmp="$(dirname "$target")/.${target##*/}.recover.$$"
      cp -a -- "$backup" "$tmp" || return 1
      fsync_path "$tmp" || return 1
      mv -f -- "$tmp" "$target" || return 1
    else
      [[ ! -e "$TX_BACKUP/$name.present" && ! -e "$backup" ]] || return 1
      rm -f -- "$target" || return 1
    fi
    fsync_path "$(dirname "$target")" || return 1
  done
}

assert_no_symlink_components() {
  local path="$1" relative current component
  local -a components=()
  [[ "$path" == /* ]] || return 1
  if [[ -n "$ROOT" ]]; then
    [[ "$path" == "$ROOT" || "$path" == "$ROOT"/* ]] || return 1
    relative="${path#"$ROOT"}"
    relative="${relative#/}"
    current="$ROOT"
  else
    relative="${path#/}"
    current=""
  fi
  IFS=/ read -r -a components <<<"$relative"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || return 1
    current="$current/$component"
    [[ ! -L "$current" ]] || return 1
  done
}

inventory_directories() {
  local i path mode
  for ((i = 0; i < ${#DIRECTORY_PATHS[@]}; i++)); do
    path="${DIRECTORY_PATHS[i]}"
    assert_no_symlink_components "$path" || return 1
    if [[ -e "$path" ]]; then
      [[ -d "$path" && ! -L "$path" ]] || return 1
      [[ "$(stat -c '%u' "$path")" == "$EXPECT_UID" ]] || return 1
      [[ "$(stat -c '%g' "$path")" == "$EXPECT_GID" ]] || return 1
      mode="$(stat -c '%a' "$path")"
      # Existing root-owned parents are preserved byte-for-byte and must not
      # be group/world writable. The private inbox is stricter.
      (( (8#$mode & 0022) == 0 )) || return 1
      case "${DIRECTORY_NAMES[i]}" in
        inbox|authorizations|consumed_authorizations|helper_backups|helper_records)
          [[ "$mode" == 700 ]] || return 1
          ;;
      esac
      TX_DIRECTORY_EXISTED[i]=1
      TX_DIRECTORY_MODE[i]="$mode"
      TX_DIRECTORY_UID[i]="$EXPECT_UID"
      TX_DIRECTORY_GID[i]="$EXPECT_GID"
    else
      TX_DIRECTORY_EXISTED[i]=0
      TX_DIRECTORY_MODE[i]=absent
      TX_DIRECTORY_UID[i]=absent
      TX_DIRECTORY_GID[i]=absent
    fi
  done
}

ensure_state_directory() {
  local path="$1"
  assert_no_symlink_components "$path" || return 1
  [[ -d "$path" && ! -L "$path" ]] || return 1
  [[ "$(stat -c '%a:%u:%g' "$path")" == "700:$EXPECT_UID:$EXPECT_GID" ]] || return 1
}

ensure_directories() {
  local i path
  for ((i = 0; i < ${#DIRECTORY_PATHS[@]}; i++)); do
    path="${DIRECTORY_PATHS[i]}"
    if [[ "${TX_DIRECTORY_EXISTED[i]}" == 0 ]]; then
      install -d -o "$EXPECT_UID" -g "$EXPECT_GID" \
        -m "${DIRECTORY_CREATE_MODES[i]}" "$path" || return 1
      fsync_path "$(dirname "$path")" || return 1
    fi
  done
}

restore_directories() {
  local i path
  for ((i = ${#DIRECTORY_PATHS[@]} - 1; i >= 0; i--)); do
    path="${DIRECTORY_PATHS[i]}"
    assert_no_symlink_components "$path" || return 1
    if [[ "${TX_DIRECTORY_EXISTED[i]}" == 0 ]]; then
      if [[ -e "$path" ]]; then
        rmdir -- "$path" || return 1
        fsync_path "$(dirname "$path")" || return 1
      fi
    else
      [[ -d "$path" && ! -L "$path" ]] || return 1
      [[ "$(stat -c '%a' "$path")" == "${TX_DIRECTORY_MODE[i]}" ]] || return 1
      [[ "$(stat -c '%u' "$path")" == "${TX_DIRECTORY_UID[i]}" ]] || return 1
      [[ "$(stat -c '%g' "$path")" == "${TX_DIRECTORY_GID[i]}" ]] || return 1
    fi
  done
}

revoke_bootstrap() {
  [[ ! -e "$TX_BOOTSTRAP" || ( -d "$TX_BOOTSTRAP" && ! -L "$TX_BOOTSTRAP" ) ]] || return 1
  assert_no_symlink_components "$TX_BOOTSTRAP" || return 1
  rm -rf -- "$TX_BOOTSTRAP" || return 1
  fsync_path "$(dirname "$TX_BOOTSTRAP")"
}

remove_uncommitted_nonce() {
  local nonce_path="$NONCE_ROOT/$TX_NONCE"
  # Journals written by the previously landed provisioner did not record the
  # nonce. Preserve an unknown consumed marker fail-closed while still
  # restoring the remaining transaction state and revoking bootstrap access.
  [[ -n "$TX_NONCE" ]] || return 0
  [[ "$TX_NONCE" =~ ^[A-Za-z0-9._-]{20,120}$ ]] || return 1
  assert_no_symlink_components "$nonce_path" || return 1
  [[ ! -L "$nonce_path" ]] || return 1
  rm -f -- "$nonce_path" || return 1
  fsync_path "$NONCE_ROOT"
}

installed_generation_ok() {
  [[ -f "$HELPER_TARGET" && ! -L "$HELPER_TARGET" && "$(stat -c '%a' "$HELPER_TARGET")" == 755 ]] || return 1
  [[ -f "$BROKER_TARGET" && ! -L "$BROKER_TARGET" && "$(stat -c '%a' "$BROKER_TARGET")" == 755 ]] || return 1
  [[ -f "$SUDOERS_TARGET" && ! -L "$SUDOERS_TARGET" && "$(stat -c '%a' "$SUDOERS_TARGET")" == 440 ]] || return 1
  [[ -f "$CONFIG_TARGET" && ! -L "$CONFIG_TARGET" && "$(stat -c '%a' "$CONFIG_TARGET")" == 600 ]] || return 1
  [[ -f "$LOCK_TARGET" && ! -L "$LOCK_TARGET" && "$(stat -c '%a' "$LOCK_TARGET")" == 600 ]] || return 1
  for installed in "$HELPER_TARGET" "$BROKER_TARGET" "$SUDOERS_TARGET" "$CONFIG_TARGET"; do
    [[ "$(stat -c '%u' "$installed")" == "$EXPECT_UID" ]] || return 1
    [[ "$(stat -c '%g' "$installed")" == "$EXPECT_GID" ]] || return 1
  done
  [[ -d "$INBOX_ROOT" && ! -L "$INBOX_ROOT" && "$(stat -c '%a' "$INBOX_ROOT")" == 700 ]] || return 1
  [[ "$(stat -c '%u' "$INBOX_ROOT")" == "$EXPECT_UID" && "$(stat -c '%g' "$INBOX_ROOT")" == "$EXPECT_GID" ]] || return 1
  [[ "$(sha "$HELPER_TARGET")" == "$TX_HELPER_SHA" ]] || return 1
  [[ "$(sha "$BROKER_TARGET")" == "$TX_BROKER_SHA" ]] || return 1
  [[ "$(sha "$SUDOERS_TARGET")" == "$TX_SUDOERS_SHA" ]] || return 1
  [[ "$(sha "$CONFIG_TARGET")" == "$TX_CONFIG_SHA" ]] || return 1
  [[ ! -e "$LEGACY_BROKER_TARGET" && ! -e "$LEGACY_SUDOERS_TARGET" ]] || return 1
  visudo -cf "$SUDOERS_TARGET" >/dev/null 2>&1
}

load_journal() {
  TX_STATE="$(journal_get state)" || return 1
  TX_DEPLOYMENT="$(journal_get deployment_id)" || return 1
  TX_COMMIT="$(journal_get commit)" || return 1
  TX_BACKUP="$(journal_get backup)" || return 1
  TX_BOOTSTRAP="$(journal_get bootstrap_root)" || return 1
  TX_HELPER_SHA="$(journal_get helper_sha)" || return 1
  TX_BROKER_SHA="$(journal_get broker_sha)" || return 1
  TX_SUDOERS_SHA="$(journal_get sudoers_sha)" || return 1
  TX_CONFIG_SHA="$(journal_get config_sha)" || return 1
  TX_GROUP_EXISTED="$(journal_get group_existed)" || return 1
  TX_MEMBER_EXISTED="$(journal_get member_existed)" || return 1
  TX_RUNNER_USER="$(journal_get runner_user)" || return 1
  if ! TX_NONCE="$(journal_get nonce)"; then
    TX_NONCE=""
  fi
  local i name
  for ((i = 0; i < ${#DIRECTORY_NAMES[@]}; i++)); do
    name="${DIRECTORY_NAMES[i]}"
    TX_DIRECTORY_EXISTED[i]="$(journal_get "dir_${name}_existed")" || return 1
    TX_DIRECTORY_MODE[i]="$(journal_get "dir_${name}_mode")" || return 1
    TX_DIRECTORY_UID[i]="$(journal_get "dir_${name}_uid")" || return 1
    TX_DIRECTORY_GID[i]="$(journal_get "dir_${name}_gid")" || return 1
    [[ "${TX_DIRECTORY_EXISTED[i]}" =~ ^[01]$ ]] || return 1
    if [[ "${TX_DIRECTORY_EXISTED[i]}" == 1 ]]; then
      [[ "${TX_DIRECTORY_MODE[i]}" =~ ^[0-7]{3,4}$ ]] || return 1
      [[ "${TX_DIRECTORY_UID[i]}" =~ ^[0-9]+$ && "${TX_DIRECTORY_GID[i]}" =~ ^[0-9]+$ ]] || return 1
    else
      [[ "${TX_DIRECTORY_MODE[i]}:${TX_DIRECTORY_UID[i]}:${TX_DIRECTORY_GID[i]}" == absent:absent:absent ]] || return 1
    fi
  done
  [[ "$TX_COMMIT" =~ ^[0-9a-f]{40}$ ]] || return 1
  [[ "$TX_DEPLOYMENT" =~ ^[A-Za-z0-9._-]{1,80}$ ]] || return 1
  [[ "$TX_BOOTSTRAP" == "$DEPLOY_ROOT/bootstrap/$TX_DEPLOYMENT" ]] || return 1
  if [[ "$TX_STATE" == AUTHORITY_ISSUED ]]; then
    [[ -z "$TX_HELPER_SHA$TX_BROKER_SHA$TX_SUDOERS_SHA$TX_CONFIG_SHA" ]] || return 1
  else
    [[ "$TX_HELPER_SHA$TX_BROKER_SHA$TX_SUDOERS_SHA$TX_CONFIG_SHA" =~ ^[0-9a-f]{256}$ ]] || return 1
  fi
  [[ "$TX_GROUP_EXISTED" =~ ^[01]$ && "$TX_MEMBER_EXISTED" =~ ^[01]$ ]] || return 1
  [[ "$TX_RUNNER_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ && "$TX_RUNNER_USER" != root ]] || return 1
  [[ -z "$TX_NONCE" || "$TX_NONCE" =~ ^[A-Za-z0-9._-]{20,120}$ ]] || return 1
  RUNNER_USER="$TX_RUNNER_USER"
  if [[ "$TX_STATE" != AUTHORITY_ISSUED ]]; then
    [[ -d "$TX_BACKUP" && ! -L "$TX_BACKUP" ]] || return 1
    [[ "$(realpath -e -- "$TX_BACKUP")" == "$(realpath -e -- "$BACKUP_ROOT")"/* ]] || return 1
  fi
}

group_exists() {
  if (( TEST_MODE )); then
    [[ -f "$STATE_ROOT/test-group-exists" ]]
  else
    getent group disk-arcana-deploy >/dev/null 2>&1
  fi
}

member_exists() {
  if (( TEST_MODE )); then
    [[ -f "$STATE_ROOT/test-member-exists" ]]
  else
    id -nG "$RUNNER_USER" | tr ' ' '\n' | grep -qxF disk-arcana-deploy
  fi
}

create_group() {
  if (( TEST_MODE )); then
    : >"$STATE_ROOT/test-group-exists"
  else
    groupadd --system disk-arcana-deploy
  fi
}

add_member() {
  if (( TEST_MODE )); then
    : >"$STATE_ROOT/test-member-exists"
  else
    usermod -a -G disk-arcana-deploy "$RUNNER_USER"
  fi
}

effective_nopasswd_commands() {
  local listing
  set +e
  listing="$(sudo -n -l -U "$RUNNER_USER" 2>&1)"
  set -e
  if printf '%s\n' "$listing" | grep -q 'NOPASSWD:'; then
    printf '%s\n' "$listing" | awk '
      /NOPASSWD:/ {
        sub(/^[[:space:]]*\([^)]*\)[[:space:]]*NOPASSWD:[[:space:]]*/, "")
        print
      }
    '
  fi
}

effective_sudo_is_prebootstrap_safe() {
  local command
  local -a commands=()
  mapfile -t commands < <(effective_nopasswd_commands)
  for command in "${commands[@]}"; do
    [[ "$command" == /usr/local/sbin/disk-arcana-install-unit ||
      "$command" == '/usr/local/sbin/disk-arcana-deploy-broker --deploy *' ]] || return 1
  done
}

effective_sudo_is_broker_only() {
  local -a commands=()
  mapfile -t commands < <(effective_nopasswd_commands)
  [[ "${#commands[@]}" -eq 1 ]] || return 1
  [[ "${commands[0]}" == '/usr/local/sbin/disk-arcana-deploy-broker --deploy *' ]]
}

restore_privilege_state() {
  if [[ "$TX_MEMBER_EXISTED" == 0 ]] && member_exists; then
    if (( TEST_MODE )); then
      rm -f -- "$STATE_ROOT/test-member-exists"
    else
      gpasswd -d "$RUNNER_USER" disk-arcana-deploy >/dev/null 2>&1 || return 1
    fi
  fi
  if [[ "$TX_GROUP_EXISTED" == 0 ]] && group_exists; then
    member_exists && return 1
    if (( TEST_MODE )); then
      rm -f -- "$STATE_ROOT/test-group-exists"
    else
      groupdel disk-arcana-deploy || return 1
    fi
  fi
}

remove_uncommitted_backup() {
  local backup_parent
  backup_parent="$(dirname "$TX_BACKUP")" || return 1
  [[ "$backup_parent" == "$BACKUP_ROOT" ]] || return 1
  assert_no_symlink_components "$TX_BACKUP" || return 1
  if [[ -e "$TX_BACKUP" ]]; then
    [[ -d "$TX_BACKUP" && ! -L "$TX_BACKUP" ]] || return 1
    rm -rf -- "$TX_BACKUP" || return 1
    fsync_path "$BACKUP_ROOT" || return 1
  fi
}

recover_unfinished() {
  local recovered_state rollback_status=0
  [[ -f "$JOURNAL" && ! -L "$JOURNAL" ]] || return 0
  load_journal || return 1
  assert_no_symlink_components "$TX_BOOTSTRAP" || return 1
  if [[ "$TX_STATE" != BOOTSTRAP_REVOKED && "$TX_STATE" != COMMITTED && -e "$TX_BOOTSTRAP" ]]; then
    [[ -d "$TX_BOOTSTRAP" && ! -L "$TX_BOOTSTRAP" ]] || return 1
    [[ "$(stat -c '%a:%u:%g' "$TX_BOOTSTRAP")" == "700:$EXPECT_UID:$EXPECT_GID" ]] || return 1
  fi
  recovered_state="$TX_STATE"
  case "$TX_STATE" in
    BOOTSTRAP_REVOKED|COMMITTED)
      installed_generation_ok || return 1
      TX_STATE=COMMITTED
      write_journal || return 1
      archive_journal committed-recovered || return 1
      printf 'state=COMMITTED recovered_from=%s\n' "$recovered_state"
      ;;
    AUTHORITY_ISSUED)
      if ! remove_uncommitted_backup; then rollback_status=1; fi
      if ! remove_uncommitted_nonce; then rollback_status=1; fi
      if ! restore_directories; then rollback_status=1; fi
      if ! revoke_bootstrap; then rollback_status=1; fi
      (( rollback_status == 0 )) || return 1
      TX_STATE=FAILED_RECOVERED
      write_journal || return 1
      archive_journal authority-revoked || return 1
      printf 'state=FAILED_RECOVERED recovered_from=%s\n' "$recovered_state"
      ;;
    BACKUP_WRITTEN|INSTALLED|NARROW_RULE_VERIFIED)
      if should_fail_at ROLLBACK_RESTORE_TARGETS || ! restore_targets; then
        rollback_status=1
      fi
      if ! restore_privilege_state; then rollback_status=1; fi
      if ! remove_uncommitted_nonce; then rollback_status=1; fi
      if ! restore_directories; then rollback_status=1; fi
      if ! revoke_bootstrap; then rollback_status=1; fi
      (( rollback_status == 0 )) || return 1
      TX_STATE=FAILED_RECOVERED
      write_journal || return 1
      archive_journal failed-recovered || return 1
      printf 'state=FAILED_RECOVERED recovered_from=%s\n' "$recovered_state"
      ;;
    *) return 1 ;;
  esac
}

rollback_failure() {
  local message="${1:-broker provisioning failed after authority issuance}"
  printf 'ERROR: %s\n' "$message" >&2
  if [[ -f "$JOURNAL" ]] && recover_unfinished; then
    exit 1
  fi
  revoke_bootstrap || true
  TX_STATE=FAILED_RECOVERY_REQUIRED
  write_journal || true
  exit 1
}

should_fail_at() {
  (( TEST_MODE )) && [[ "${DISK_ARCANA_PROVISION_TEST_FAIL_AT:-}" == "$1" ]]
}

for recovery_path in "$STATE_ROOT" "$NONCE_ROOT" "$RECORD_ROOT" "$BACKUP_ROOT" \
  "$HELPER_TARGET" "$BROKER_TARGET" "$SUDOERS_TARGET" "$CONFIG_TARGET" "$INBOX_ROOT" "$LOCK_TARGET" \
  "$LEGACY_BROKER_TARGET" "$LEGACY_SUDOERS_TARGET"; do
  assert_no_symlink_components "$recovery_path" || die "recovery path has a symlink component"
done
ensure_state_directory "$STATE_ROOT" || die "transaction root has unsafe metadata"
ensure_state_directory "$NONCE_ROOT" || die "nonce state has unsafe metadata"
ensure_state_directory "$RECORD_ROOT" || die "provision records have unsafe metadata"
ensure_state_directory "$BACKUP_ROOT" || die "provision backups have unsafe metadata"

recover_unfinished || die "unfinished broker provisioning could not be recovered"

[[ "$BUNDLE" == /* && -d "$BUNDLE" && ! -L "$BUNDLE" ]] || die "unsafe bootstrap bundle"
[[ "$AUTH" == /* && -f "$AUTH" && ! -L "$AUTH" && "$(stat -c '%a' "$AUTH")" == 600 ]] || die "unsafe authorization packet"

DEPLOYMENT_ID="" RUN_ID="" COMMIT="" MANIFEST_SHA="" EXPECTED_HOST="" NONCE="" EXPIRES=""
RUNNER_USER="" RUNNER_GROUP="" IMPORT_ROOT="" BOOTSTRAP_ROOT=""
declare -A AUTH_SEEN=()
while IFS='=' read -r key value; do
  [[ -z "${AUTH_SEEN[$key]+present}" ]] || die "duplicate authorization key"
  AUTH_SEEN["$key"]=1
  case "$key" in
    deployment_id) DEPLOYMENT_ID="$value" ;;
    run_id) RUN_ID="$value" ;;
    commit) COMMIT="$value" ;;
    manifest_sha) MANIFEST_SHA="$value" ;;
    hostname) EXPECTED_HOST="$value" ;;
    nonce) NONCE="$value" ;;
    expires) EXPIRES="$value" ;;
    runner_user) RUNNER_USER="$value" ;;
    runner_group) RUNNER_GROUP="$value" ;;
    import_root) IMPORT_ROOT="$value" ;;
    bootstrap_root) BOOTSTRAP_ROOT="$value" ;;
    *) die "unknown authorization key" ;;
  esac
done <"$AUTH"

[[ "$DEPLOYMENT_ID" =~ ^[A-Za-z0-9._-]{1,80}$ ]] || die "invalid deployment id"
[[ "$RUN_ID" =~ ^[0-9]{1,20}$ ]] || die "invalid workflow run id"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "invalid authorized commit"
[[ "$MANIFEST_SHA" =~ ^[0-9a-f]{64}$ ]] || die "invalid manifest identity"
[[ "$EXPECTED_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || die "invalid hostname"
[[ "$NONCE" =~ ^[A-Za-z0-9._-]{20,120}$ ]] || die "invalid authorization nonce"
[[ "$EXPIRES" =~ ^[0-9]{10,12}$ && "$EXPIRES" -gt "$(date +%s)" ]] || die "authorization expired"
[[ "$RUNNER_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ && "$RUNNER_USER" != root ]] || die "invalid runner user"
[[ "$RUNNER_GROUP" == disk-arcana-deploy ]] || die "unexpected runner group"
[[ "$IMPORT_ROOT" == /* && "$IMPORT_ROOT" != / && -d "$IMPORT_ROOT" && ! -L "$IMPORT_ROOT" ]] || die "unsafe import root"
[[ "$BOOTSTRAP_ROOT" == /* && "$BOOTSTRAP_ROOT" != / && -d "$BOOTSTRAP_ROOT" && ! -L "$BOOTSTRAP_ROOT" ]] || die "unsafe bootstrap root"
[[ "$BOOTSTRAP_ROOT" == "$DEPLOY_ROOT/bootstrap/$DEPLOYMENT_ID" ]] || die "bootstrap root is not canonical"
assert_no_symlink_components "$BOOTSTRAP_ROOT" || die "bootstrap path has a symlink component"
[[ "$(stat -c '%a:%u:%g' "$BOOTSTRAP_ROOT")" == "700:$EXPECT_UID:$EXPECT_GID" ]] ||
  die "bootstrap root has unsafe metadata"
[[ "$(stat -c '%a:%u:%g' "$BUNDLE")" == "700:$EXPECT_UID:$EXPECT_GID" ]] ||
  die "bootstrap bundle has unsafe metadata"
[[ "$(stat -c '%u:%g' "$AUTH")" == "$EXPECT_UID:$EXPECT_GID" ]] ||
  die "authorization packet is not root-issued"
for owned_ancestor in "$DEPLOY_ROOT" "$DEPLOY_ROOT/bootstrap"; do
  [[ -d "$owned_ancestor" && ! -L "$owned_ancestor" ]] || die "bootstrap ancestor is unsafe"
  [[ "$(stat -c '%u:%g' "$owned_ancestor")" == "$EXPECT_UID:$EXPECT_GID" ]] ||
    die "bootstrap ancestor has unsafe ownership"
  ancestor_mode="$(stat -c '%a' "$owned_ancestor")"
  (( (8#$ancestor_mode & 0022) == 0 )) || die "bootstrap ancestor is group/world writable"
done
[[ "$(realpath -e -- "$AUTH")" == "$(realpath -e -- "$BOOTSTRAP_ROOT")"/* ]] || die "authorization is outside bootstrap root"
[[ "$(realpath -e -- "$BUNDLE")" == "$(realpath -e -- "$BOOTSTRAP_ROOT")"/* ]] || die "bundle is outside bootstrap root"
[[ "$(hostname 2>/dev/null)" == "$EXPECTED_HOST" ]] || die "hostname mismatch"
[[ "$(sha "$BUNDLE/manifest.sha256")" == "$MANIFEST_SHA" ]] || die "manifest identity mismatch"
[[ ! -e "$NONCE_ROOT/$NONCE" ]] || die "authorization nonce was already consumed"

is_member() {
  local wanted="$1" candidate
  for candidate in "${MEMBERS[@]}"; do
    [[ "$wanted" == "$candidate" ]] && return 0
  done
  return 1
}

validate_bundle() {
  local marker="__disk_arcana_inventory_success__" status=0 count i path member row line=0 digest
  local -a inventory=()
  mapfile -d '' -t inventory < <(
    find "$BUNDLE" -mindepth 1 -maxdepth 1 -print0 || status=$?
    (( status == 0 )) && printf '%s\0' "$marker"
  )
  count=${#inventory[@]}
  [[ "$count" -eq $((${#MEMBERS[@]} + 2)) ]] || return 1
  [[ "${inventory[$((count - 1))]}" == "$marker" ]] || return 1
  for ((i = 0; i < count - 1; i++)); do
    path="${inventory[i]}"; member="${path##*/}"
    [[ "$member" == manifest.sha256 ]] || is_member "$member" || return 1
    [[ -f "$path" && ! -L "$path" ]] || return 1
  done
  awk -v expected="$COMMIT" 'NR == 1 {value=$0} NR > 1 {extra=1}
    END {exit !(NR == 1 && !extra && value == expected)}' "$BUNDLE/commit" || return 1
  while IFS= read -r row || [[ -n "$row" ]]; do
    line=$((line + 1))
    [[ "$row" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([^[:space:]]+)$ ]] || return 1
    digest="${BASH_REMATCH[1]}"; member="${BASH_REMATCH[2]}"
    (( line <= ${#MEMBERS[@]} )) || return 1
    [[ "$member" == "${MEMBERS[$((line - 1))]}" ]] || return 1
    [[ "$(sha "$BUNDLE/$member")" == "$digest" ]] || return 1
  done <"$BUNDLE/manifest.sha256"
  [[ "$line" -eq "${#MEMBERS[@]}" ]] || return 1
  [[ "$(sha "$BUNDLE/provision-deploy-broker.sh")" == "$(sha "$0")" ]] || return 1
}

validate_bundle || die "bundle validation failed"

effective_sudo_is_prebootstrap_safe || die "effective passwordless sudo exceeds the legacy migration allowance"

if (( ! TEST_MODE )); then
  id -u "$RUNNER_USER" >/dev/null 2>&1 || die "runner user does not exist"
fi

TX_DEPLOYMENT="$DEPLOYMENT_ID"
TX_COMMIT="$COMMIT"
TX_BOOTSTRAP="$BOOTSTRAP_ROOT"
TX_RUNNER_USER="$RUNNER_USER"
TX_NONCE="$NONCE"
if group_exists; then TX_GROUP_EXISTED=1; else TX_GROUP_EXISTED=0; fi
if member_exists; then TX_MEMBER_EXISTED=1; else TX_MEMBER_EXISTED=0; fi
backup_timestamp="$(date -u +%Y%m%dT%H%M%SZ)" || die "could not timestamp transaction backup"
TX_BACKUP="$BACKUP_ROOT/$backup_timestamp-$$"
inventory_directories || die "privileged directory inventory failed"
transition AUTHORITY_ISSUED || rollback_failure "could not persist issued bootstrap authority"

should_fail_at PREPARE_DIRECTORIES && rollback_failure "injected directory preparation failure"
ensure_directories || rollback_failure "could not prepare privileged directories"
install -d -o "$EXPECT_UID" -g "$EXPECT_GID" -m 0700 "$TX_BACKUP" ||
  rollback_failure "could not prepare transaction backup"
tmp_helper="$TX_BACKUP/new-helper"
tmp_broker="$TX_BACKUP/new-broker"
tmp_sudoers="$TX_BACKUP/new-sudoers"
tmp_config="$TX_BACKUP/new-config"
tmp_lock="$TX_BACKUP/new-lock"
should_fail_at STAGE_HELPER && rollback_failure "injected helper staging failure"
install -m 0755 "$BUNDLE/deploy-server.sh" "$tmp_helper" || rollback_failure "could not stage deploy helper"
install -m 0755 "$BUNDLE/deploy-server-broker.sh" "$tmp_broker" || rollback_failure "could not stage deploy broker"
install -m 0440 "$BUNDLE/disk-arcana-deploy.sudoers" "$tmp_sudoers" || rollback_failure "could not stage sudoers policy"
{
  printf 'runner_user=%s\n' "$RUNNER_USER"
  printf 'runner_group=%s\n' "$RUNNER_GROUP"
  printf 'import_root=%s\n' "$IMPORT_ROOT"
  printf 'expected_hostname=%s\n' "$EXPECTED_HOST"
} >"$tmp_config" || rollback_failure "could not stage broker configuration"
chmod 0600 "$tmp_config" || rollback_failure "could not secure broker configuration"
install -m 0600 /dev/null "$tmp_lock" || rollback_failure "could not stage deployment lock"
visudo -cf "$tmp_sudoers" >/dev/null 2>&1 || rollback_failure "sudoers policy validation failed"
for staged in "$tmp_helper" "$tmp_broker" "$tmp_sudoers" "$tmp_config" "$tmp_lock"; do
  fsync_path "$staged" || rollback_failure "could not fsync staged broker file"
done
should_fail_at HASH_STAGED && rollback_failure "injected staged hash failure"
TX_HELPER_SHA="$(sha "$tmp_helper")" || rollback_failure "could not hash staged helper"
TX_BROKER_SHA="$(sha "$tmp_broker")" || rollback_failure "could not hash staged broker"
TX_SUDOERS_SHA="$(sha "$tmp_sudoers")" || rollback_failure "could not hash staged sudoers"
TX_CONFIG_SHA="$(sha "$tmp_config")" || rollback_failure "could not hash staged configuration"
fsync_path "$TX_BACKUP" || rollback_failure "could not fsync broker backup directory"
fsync_path "$BACKUP_ROOT" || rollback_failure "could not fsync broker backup root"

for ((i = 0; i < ${#TARGETS[@]}; i++)); do
  name="${TARGET_NAMES[i]}"; target="${TARGETS[i]}"
  if (( i == 0 )) && should_fail_at BACKUP_TARGET; then
    rollback_failure "injected target backup failure"
  fi
  [[ ! -L "$target" ]] || rollback_failure "unsafe existing broker target"
  if [[ -e "$target" ]]; then
    [[ -f "$target" ]] || rollback_failure "existing broker target is not regular"
    cp -a -- "$target" "$TX_BACKUP/$name" || rollback_failure "could not back up broker target"
    : >"$TX_BACKUP/$name.present" || rollback_failure "could not write backup marker"
    fsync_path "$TX_BACKUP/$name" || rollback_failure "could not fsync broker backup"
    fsync_path "$TX_BACKUP/$name.present" || rollback_failure "could not fsync backup marker"
  fi
done
fsync_path "$TX_BACKUP" || rollback_failure "could not fsync broker backup directory"
transition BACKUP_WRITTEN || rollback_failure "could not persist broker backup transaction"

group_exists || create_group || rollback_failure
member_exists || add_member || rollback_failure

mv -f -- "$tmp_helper" "$HELPER_TARGET" || rollback_failure
mv -f -- "$tmp_broker" "$BROKER_TARGET" || rollback_failure
mv -f -- "$tmp_sudoers" "$SUDOERS_TARGET" || rollback_failure
mv -f -- "$tmp_config" "$CONFIG_TARGET" || rollback_failure
mv -f -- "$tmp_lock" "$LOCK_TARGET" || rollback_failure
rm -f -- "$LEGACY_BROKER_TARGET" "$LEGACY_SUDOERS_TARGET" || rollback_failure
for parent in "$(dirname "$HELPER_TARGET")" "$(dirname "$BROKER_TARGET")" \
  "$(dirname "$SUDOERS_TARGET")" "$(dirname "$CONFIG_TARGET")" \
  "$(dirname "$LOCK_TARGET")"; do
  fsync_path "$parent" || rollback_failure
done
transition INSTALLED || rollback_failure

installed_generation_ok || rollback_failure
effective_sudo_is_broker_only || rollback_failure
transition NARROW_RULE_VERIFIED || rollback_failure
if (( TEST_MODE )) && [[ "${DISK_ARCANA_PROVISION_TEST_FAIL_AT:-}" == NARROW_RULE_VERIFIED ]]; then
  rollback_failure
fi
if should_fail_at ROLLBACK_RESTORE_TARGETS; then
  rollback_failure "injected rollback restoration failure"
fi

if should_fail_at WRITE_NONCE || ! : >"$NONCE_ROOT/$NONCE"; then
  rollback_failure "could not persist consumed authorization nonce"
fi
if should_fail_at CHMOD_NONCE || ! chmod 0600 "$NONCE_ROOT/$NONCE"; then
  rollback_failure "could not secure consumed authorization nonce"
fi
fsync_path "$NONCE_ROOT/$NONCE" || rollback_failure
fsync_path "$NONCE_ROOT" || rollback_failure

revoke_bootstrap || rollback_failure
transition BOOTSTRAP_REVOKED || rollback_failure
transition COMMITTED || rollback_failure
archive_journal committed || rollback_failure "could not archive committed broker transaction"
printf 'state=COMMITTED deployment_id=%s commit=%s\n' "$DEPLOYMENT_ID" "$COMMIT"
