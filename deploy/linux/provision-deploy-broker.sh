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
  provision-deploy-broker.sh
)
readonly -a TARGET_NAMES=(helper broker sudoers config)

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

readonly STATE_ROOT="$ROOT/var/lib/disk-arcana/deploy-transactions"
readonly NONCE_ROOT="$STATE_ROOT/used-authorizations"
readonly RECORD_ROOT="$STATE_ROOT/provision-records"
readonly BACKUP_ROOT="$STATE_ROOT/provision-backups"
readonly JOURNAL="$STATE_ROOT/provision-current"
readonly HELPER_TARGET="$ROOT/usr/local/libexec/disk-arcana/deploy-server.sh"
readonly BROKER_TARGET="$ROOT/usr/local/sbin/disk-arcana-deploy-broker"
readonly SUDOERS_TARGET="$ROOT/etc/sudoers.d/disk-arcana-deploy"
readonly CONFIG_TARGET="$ROOT/etc/disk-arcana/deploy.conf"
readonly INBOX_ROOT="$ROOT/var/lib/disk-arcana/deploy-inbox"
readonly -a TARGETS=("$HELPER_TARGET" "$BROKER_TARGET" "$SUDOERS_TARGET" "$CONFIG_TARGET")

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

write_journal() {
  local tmp="$STATE_ROOT/.provision-current.$$"
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
    printf 'timestamp=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$tmp"
  chmod 0600 "$tmp"
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
  local suffix="$1" record
  record="$RECORD_ROOT/$(date -u +%Y%m%dT%H%M%SZ)-$$-$suffix"
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

installed_generation_ok() {
  [[ -f "$HELPER_TARGET" && ! -L "$HELPER_TARGET" && "$(stat -c '%a' "$HELPER_TARGET")" == 755 ]] || return 1
  [[ -f "$BROKER_TARGET" && ! -L "$BROKER_TARGET" && "$(stat -c '%a' "$BROKER_TARGET")" == 755 ]] || return 1
  [[ -f "$SUDOERS_TARGET" && ! -L "$SUDOERS_TARGET" && "$(stat -c '%a' "$SUDOERS_TARGET")" == 440 ]] || return 1
  [[ -f "$CONFIG_TARGET" && ! -L "$CONFIG_TARGET" && "$(stat -c '%a' "$CONFIG_TARGET")" == 600 ]] || return 1
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
  [[ "$TX_COMMIT" =~ ^[0-9a-f]{40}$ ]] || return 1
  [[ "$TX_DEPLOYMENT" =~ ^[A-Za-z0-9._-]{1,80}$ ]] || return 1
  [[ "$TX_BOOTSTRAP" == "$ROOT/var/lib/disk-arcana/bootstrap/$TX_DEPLOYMENT" ]] || return 1
  [[ "$TX_HELPER_SHA$TX_BROKER_SHA$TX_SUDOERS_SHA$TX_CONFIG_SHA" =~ ^[0-9a-f]{256}$ ]] || return 1
  [[ "$TX_GROUP_EXISTED" =~ ^[01]$ && "$TX_MEMBER_EXISTED" =~ ^[01]$ ]] || return 1
  [[ -d "$TX_BACKUP" && ! -L "$TX_BACKUP" ]] || return 1
  [[ "$(realpath -e -- "$TX_BACKUP")" == "$(realpath -e -- "$BACKUP_ROOT")"/* ]] || return 1
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

recover_unfinished() {
  local recovered_state
  [[ -f "$JOURNAL" && ! -L "$JOURNAL" ]] || return 0
  load_journal || return 1
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
      [[ ! -e "$TX_BOOTSTRAP" || ( -d "$TX_BOOTSTRAP" && ! -L "$TX_BOOTSTRAP" ) ]] || return 1
      rm -rf -- "$TX_BOOTSTRAP"
      fsync_path "$(dirname "$TX_BOOTSTRAP")" || return 1
      TX_STATE=FAILED_RECOVERED
      write_journal || return 1
      archive_journal authority-revoked || return 1
      printf 'state=FAILED_RECOVERED recovered_from=%s\n' "$recovered_state"
      ;;
    BACKUP_WRITTEN|INSTALLED|NARROW_RULE_VERIFIED)
      restore_targets || return 1
      restore_privilege_state || return 1
      [[ ! -e "$TX_BOOTSTRAP" || ( -d "$TX_BOOTSTRAP" && ! -L "$TX_BOOTSTRAP" ) ]] || return 1
      rm -rf -- "$TX_BOOTSTRAP"
      fsync_path "$(dirname "$TX_BOOTSTRAP")" || return 1
      TX_STATE=FAILED_RECOVERED
      write_journal || return 1
      archive_journal failed-recovered || return 1
      printf 'state=FAILED_RECOVERED recovered_from=%s\n' "$recovered_state"
      ;;
    *) return 1 ;;
  esac
}

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
[[ "$BOOTSTRAP_ROOT" == "$ROOT/var/lib/disk-arcana/bootstrap/$DEPLOYMENT_ID" ]] || die "bootstrap root is not canonical"
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

while IFS= read -r policy; do
  [[ "$policy" == "$SUDOERS_TARGET" ]] && continue
  if awk -v user="$RUNNER_USER" -v group="%$RUNNER_GROUP" '
    /NOPASSWD:/ && (index($0, user) || index($0, group)) {found=1}
    END {exit !found}
  ' "$policy"; then
    die "broader passwordless sudo rule exists"
  fi
done < <(find "$ROOT/etc/sudoers" "$ROOT/etc/sudoers.d" -maxdepth 1 -type f 2>/dev/null || true)

install -d -m 0700 "$STATE_ROOT" "$NONCE_ROOT" "$RECORD_ROOT" "$BACKUP_ROOT"
install -d -m 0755 \
  "$(dirname "$HELPER_TARGET")" "$(dirname "$BROKER_TARGET")" \
  "$(dirname "$SUDOERS_TARGET")" "$(dirname "$CONFIG_TARGET")"
install -d -m 0700 "$INBOX_ROOT"
if (( ! TEST_MODE )); then
  id -u "$RUNNER_USER" >/dev/null 2>&1 || die "runner user does not exist"
fi

TX_STATE=AUTHORITY_ISSUED
TX_DEPLOYMENT="$DEPLOYMENT_ID"
TX_COMMIT="$COMMIT"
TX_BOOTSTRAP="$BOOTSTRAP_ROOT"
if group_exists; then TX_GROUP_EXISTED=1; else TX_GROUP_EXISTED=0; fi
if member_exists; then TX_MEMBER_EXISTED=1; else TX_MEMBER_EXISTED=0; fi
TX_BACKUP="$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%SZ)-$$"
install -d -m 0700 "$TX_BACKUP"
tmp_helper="$TX_BACKUP/new-helper"
tmp_broker="$TX_BACKUP/new-broker"
tmp_sudoers="$TX_BACKUP/new-sudoers"
tmp_config="$TX_BACKUP/new-config"
install -m 0755 "$BUNDLE/deploy-server.sh" "$tmp_helper"
install -m 0755 "$BUNDLE/deploy-server-broker.sh" "$tmp_broker"
install -m 0440 "$BUNDLE/disk-arcana-deploy.sudoers" "$tmp_sudoers"
{
  printf 'runner_user=%s\n' "$RUNNER_USER"
  printf 'runner_group=%s\n' "$RUNNER_GROUP"
  printf 'import_root=%s\n' "$IMPORT_ROOT"
  printf 'expected_hostname=%s\n' "$EXPECTED_HOST"
} >"$tmp_config"
chmod 0600 "$tmp_config"
visudo -cf "$tmp_sudoers" >/dev/null 2>&1 || die "sudoers policy validation failed"
for staged in "$tmp_helper" "$tmp_broker" "$tmp_sudoers" "$tmp_config"; do
  fsync_path "$staged" || die "could not fsync staged broker file"
done
TX_HELPER_SHA="$(sha "$tmp_helper")"
TX_BROKER_SHA="$(sha "$tmp_broker")"
TX_SUDOERS_SHA="$(sha "$tmp_sudoers")"
TX_CONFIG_SHA="$(sha "$tmp_config")"
fsync_path "$TX_BACKUP" || die "could not fsync broker backup directory"
fsync_path "$BACKUP_ROOT" || die "could not fsync broker backup root"
transition AUTHORITY_ISSUED || die "could not persist issued bootstrap authority"

for ((i = 0; i < ${#TARGETS[@]}; i++)); do
  name="${TARGET_NAMES[i]}"; target="${TARGETS[i]}"
  [[ ! -L "$target" ]] || die "unsafe existing broker target"
  if [[ -e "$target" ]]; then
    [[ -f "$target" ]] || die "existing broker target is not regular"
    cp -a -- "$target" "$TX_BACKUP/$name"
    : >"$TX_BACKUP/$name.present"
    fsync_path "$TX_BACKUP/$name" || die "could not fsync broker backup"
    fsync_path "$TX_BACKUP/$name.present" || die "could not fsync backup marker"
  fi
done
fsync_path "$TX_BACKUP" || die "could not fsync broker backup directory"
transition BACKUP_WRITTEN || die "could not persist broker backup transaction"

rollback_failure() {
  printf 'ERROR: broker provisioning failed after backup\n' >&2
  if restore_targets && restore_privilege_state; then
    TX_STATE=FAILED_RECOVERED
    write_journal || true
    archive_journal failed-recovered || true
  else
    TX_STATE=FAILED_RECOVERY_REQUIRED
    write_journal || true
  fi
  exit 1
}

group_exists || create_group || rollback_failure
member_exists || add_member || rollback_failure

mv -f -- "$tmp_helper" "$HELPER_TARGET" || rollback_failure
mv -f -- "$tmp_broker" "$BROKER_TARGET" || rollback_failure
mv -f -- "$tmp_sudoers" "$SUDOERS_TARGET" || rollback_failure
mv -f -- "$tmp_config" "$CONFIG_TARGET" || rollback_failure
for parent in "$(dirname "$HELPER_TARGET")" "$(dirname "$BROKER_TARGET")" \
  "$(dirname "$SUDOERS_TARGET")" "$(dirname "$CONFIG_TARGET")"; do
  fsync_path "$parent" || rollback_failure
done
transition INSTALLED || rollback_failure

installed_generation_ok || rollback_failure
transition NARROW_RULE_VERIFIED || rollback_failure
if (( TEST_MODE )) && [[ "${DISK_ARCANA_PROVISION_TEST_FAIL_AT:-}" == NARROW_RULE_VERIFIED ]]; then
  rollback_failure
fi

: >"$NONCE_ROOT/$NONCE"
chmod 0600 "$NONCE_ROOT/$NONCE"
fsync_path "$NONCE_ROOT/$NONCE" || rollback_failure
fsync_path "$NONCE_ROOT" || rollback_failure

rm -rf -- "$BOOTSTRAP_ROOT"
fsync_path "$(dirname "$BOOTSTRAP_ROOT")" || rollback_failure
transition BOOTSTRAP_REVOKED || rollback_failure
transition COMMITTED || rollback_failure
archive_journal committed || die "could not archive committed broker transaction"
printf 'state=COMMITTED deployment_id=%s commit=%s\n' "$DEPLOYMENT_ID" "$COMMIT"
