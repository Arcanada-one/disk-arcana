#!/usr/bin/env bash
# INFRA-0370: one-shot, journaled cold-host bootstrap for disk-arcana-server.
# Routine updates are handled exclusively by disk-arcana-deploy-broker.

set -euo pipefail
IFS=$'\n\t'
umask 077

ROOT=""
BINARY_PATH=""
UNIT_PATH=""
JOURNAL_DIR=""
EXPECTED_HOSTNAME=""
TEST_MODE=0
TX_STATE=""
TX_USER_EXISTED=""
TX_GROUP_EXISTED=""
TX_ENV_MODE=""
TX_ENV_UID=""
TX_ENV_GID=""

usage() {
  printf 'usage: %s --binary FILE --unit FILE --journal-dir DIR --expected-hostname HOST [--root ROOT]\n' \
    "$(basename "$0")" >&2
  exit 2
}

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) [[ $# -ge 2 ]] || usage; BINARY_PATH="$2"; shift 2 ;;
    --unit) [[ $# -ge 2 ]] || usage; UNIT_PATH="$2"; shift 2 ;;
    --journal-dir) [[ $# -ge 2 ]] || usage; JOURNAL_DIR="$2"; shift 2 ;;
    --expected-hostname) [[ $# -ge 2 ]] || usage; EXPECTED_HOSTNAME="$2"; shift 2 ;;
    --root) [[ $# -ge 2 ]] || usage; ROOT="${2%/}"; shift 2 ;;
    *) usage ;;
  esac
done

[[ -n "$BINARY_PATH" && -n "$UNIT_PATH" && -n "$JOURNAL_DIR" && -n "$EXPECTED_HOSTNAME" ]] || usage
[[ "$BINARY_PATH" == /* && -f "$BINARY_PATH" && ! -L "$BINARY_PATH" ]] || die "unsafe bootstrap binary"
[[ "$UNIT_PATH" == /* && -f "$UNIT_PATH" && ! -L "$UNIT_PATH" ]] || die "unsafe bootstrap unit"
[[ "$JOURNAL_DIR" == /* && -d "$JOURNAL_DIR" && ! -L "$JOURNAL_DIR" ]] || die "unsafe root-issued journal directory"
[[ "$EXPECTED_HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || die "invalid expected hostname"

if [[ "${DISK_ARCANA_INSTALL_TESTING:-}" == 1 ]]; then
  [[ "$(id -u)" -ne 0 ]] || die "test mode is forbidden for root invocations"
  [[ -n "$ROOT" && "$ROOT" == /* && "$ROOT" != / && -d "$ROOT" && ! -L "$ROOT" ]] || die "unsafe test root"
  TEST_MODE=1
  OWNER_UID="$(id -u)"
  OWNER_GID="$(id -g)"
  SERVICE_UID="$OWNER_UID"
  SERVICE_GID="$OWNER_GID"
else
  [[ "$(id -u)" -eq 0 ]] || die "cold bootstrap requires root"
  [[ -z "$ROOT" ]] || die "alternate root is test-only"
  [[ -z "${DISK_ARCANA_INSTALL_TEST_FAIL_AT:-}" ]] || die "test failure control is forbidden"
  [[ -z "${DISK_ARCANA_INSTALL_TEST_KILL_AFTER_STATE:-}" ]] || die "test crash control is forbidden"
  OWNER_UID=0
  OWNER_GID=0
  SERVICE_UID=""
  SERVICE_GID=""
fi
readonly TEST_MODE ROOT OWNER_UID OWNER_GID

readonly LIVE_BINARY="$ROOT/usr/local/bin/disk-arcana-server"
readonly LIVE_UNIT="$ROOT/etc/systemd/system/disk-arcana-server.service"
readonly CONFIG_ROOT="$ROOT/etc/disk-arcana"
readonly ENV_FILE="$CONFIG_ROOT/env"
readonly DATA_ROOT="$ROOT/var/lib/disk-arcana"
readonly LOG_ROOT="$ROOT/var/log/disk-arcana"
readonly JOURNAL="$JOURNAL_DIR/install-current"
readonly -a DIRECTORY_NAMES=(config tls gpg data log)
readonly -a DIRECTORY_PATHS=("$CONFIG_ROOT" "$CONFIG_ROOT/tls" "$CONFIG_ROOT/gpg" "$DATA_ROOT" "$LOG_ROOT")
readonly -a DIRECTORY_MODES=(0750 0750 0700 0750 0750)
declare -a TX_DIRECTORY_EXISTED=()
declare -a TX_DIRECTORY_MODE=()
declare -a TX_DIRECTORY_UID=()
declare -a TX_DIRECTORY_GID=()

fsync_path() { sync -f "$1" >/dev/null 2>&1; }

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

journal_get() {
  local key="$1"
  awk -F= -v wanted="$key" '$1 == wanted {sub(/^[^=]*=/, ""); print; found=1} END {if (!found) exit 1}' "$JOURNAL"
}

write_journal() {
  local tmp="$JOURNAL_DIR/.install-current.$$" i
  {
    printf 'state=%s\n' "$TX_STATE"
    printf 'user_existed=%s\n' "$TX_USER_EXISTED"
    printf 'group_existed=%s\n' "$TX_GROUP_EXISTED"
    printf 'env_mode=%s\n' "$TX_ENV_MODE"
    printf 'env_uid=%s\n' "$TX_ENV_UID"
    printf 'env_gid=%s\n' "$TX_ENV_GID"
    for ((i = 0; i < ${#DIRECTORY_NAMES[@]}; i++)); do
      printf 'dir_%s_existed=%s\n' "${DIRECTORY_NAMES[i]}" "${TX_DIRECTORY_EXISTED[i]}"
      printf 'dir_%s_mode=%s\n' "${DIRECTORY_NAMES[i]}" "${TX_DIRECTORY_MODE[i]}"
      printf 'dir_%s_uid=%s\n' "${DIRECTORY_NAMES[i]}" "${TX_DIRECTORY_UID[i]}"
      printf 'dir_%s_gid=%s\n' "${DIRECTORY_NAMES[i]}" "${TX_DIRECTORY_GID[i]}"
    done
    printf 'timestamp=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$tmp"
  chmod 0600 "$tmp"
  fsync_path "$tmp" || return 1
  mv -f -- "$tmp" "$JOURNAL" || return 1
  fsync_path "$JOURNAL_DIR"
}

transition() {
  TX_STATE="$1"
  write_journal || return 1
  if (( TEST_MODE )) && [[ "${DISK_ARCANA_INSTALL_TEST_KILL_AFTER_STATE:-}" == "$TX_STATE" ]]; then
    kill -KILL "$$"
  fi
}

inventory_directories() {
  local i path
  for ((i = 0; i < ${#DIRECTORY_PATHS[@]}; i++)); do
    path="${DIRECTORY_PATHS[i]}"
    assert_no_symlink_components "$path" || return 1
    if [[ -e "$path" ]]; then
      [[ -d "$path" && ! -L "$path" ]] || return 1
      TX_DIRECTORY_EXISTED[i]=1
      TX_DIRECTORY_MODE[i]="$(stat -c '%a' "$path")"
      TX_DIRECTORY_UID[i]="$(stat -c '%u' "$path")"
      TX_DIRECTORY_GID[i]="$(stat -c '%g' "$path")"
    else
      TX_DIRECTORY_EXISTED[i]=0
      TX_DIRECTORY_MODE[i]=absent
      TX_DIRECTORY_UID[i]=absent
      TX_DIRECTORY_GID[i]=absent
    fi
  done
}

load_journal() {
  local i name
  TX_STATE="$(journal_get state)" || return 1
  TX_USER_EXISTED="$(journal_get user_existed)" || return 1
  TX_GROUP_EXISTED="$(journal_get group_existed)" || return 1
  TX_ENV_MODE="$(journal_get env_mode)" || return 1
  TX_ENV_UID="$(journal_get env_uid)" || return 1
  TX_ENV_GID="$(journal_get env_gid)" || return 1
  [[ "$TX_USER_EXISTED" =~ ^[01]$ && "$TX_GROUP_EXISTED" =~ ^[01]$ ]] || return 1
  [[ "$TX_ENV_MODE" =~ ^[0-7]{3,4}$ && "$TX_ENV_UID" =~ ^[0-9]+$ && "$TX_ENV_GID" =~ ^[0-9]+$ ]] || return 1
  for ((i = 0; i < ${#DIRECTORY_NAMES[@]}; i++)); do
    name="${DIRECTORY_NAMES[i]}"
    TX_DIRECTORY_EXISTED[i]="$(journal_get "dir_${name}_existed")" || return 1
    TX_DIRECTORY_MODE[i]="$(journal_get "dir_${name}_mode")" || return 1
    TX_DIRECTORY_UID[i]="$(journal_get "dir_${name}_uid")" || return 1
    TX_DIRECTORY_GID[i]="$(journal_get "dir_${name}_gid")" || return 1
    [[ "${TX_DIRECTORY_EXISTED[i]}" =~ ^[01]$ ]] || return 1
  done
}

service_user_exists() {
  if (( TEST_MODE )); then [[ -f "$JOURNAL_DIR/test-user-exists" ]]; else id disk-arcana >/dev/null 2>&1; fi
}

service_group_exists() {
  if (( TEST_MODE )); then [[ -f "$JOURNAL_DIR/test-group-exists" ]]; else getent group disk-arcana >/dev/null 2>&1; fi
}

create_service_account() {
  if (( TEST_MODE )); then
    if [[ "$TX_GROUP_EXISTED" == 0 ]]; then
      : >"$JOURNAL_DIR/test-group-exists"
    fi
    : >"$JOURNAL_DIR/test-user-exists"
  else
    if [[ "$TX_GROUP_EXISTED" == 0 ]]; then
      groupadd --system disk-arcana
    fi
    useradd --system --no-create-home --shell /usr/sbin/nologin --gid disk-arcana disk-arcana
    SERVICE_UID="$(id -u disk-arcana)"; SERVICE_GID="$(id -g disk-arcana)"
  fi
}

resolve_service_ids() {
  if (( TEST_MODE )); then return 0; fi
  SERVICE_UID="$(id -u disk-arcana)" || return 1
  SERVICE_GID="$(id -g disk-arcana)" || return 1
}

ensure_directories() {
  local i path owner_uid owner_gid
  for ((i = 0; i < ${#DIRECTORY_PATHS[@]}; i++)); do
    path="${DIRECTORY_PATHS[i]}"
    case "${DIRECTORY_NAMES[i]}" in
      config|tls|gpg) owner_uid="$OWNER_UID"; owner_gid="$SERVICE_GID" ;;
      data|log) owner_uid="$SERVICE_UID"; owner_gid="$SERVICE_GID" ;;
    esac
    install -d -o "$owner_uid" -g "$owner_gid" -m "${DIRECTORY_MODES[i]}" "$path" || return 1
  done
}

restore_directories() {
  local i path
  for ((i = ${#DIRECTORY_PATHS[@]} - 1; i >= 0; i--)); do
    path="${DIRECTORY_PATHS[i]}"
    assert_no_symlink_components "$path" || return 1
    if [[ "${TX_DIRECTORY_EXISTED[i]}" == 0 ]]; then
      if [[ -e "$path" ]]; then
        rm -rf -- "$path" || return 1
        if [[ -d "$(dirname "$path")" ]]; then
          fsync_path "$(dirname "$path")" || return 1
        fi
      fi
    else
      [[ -d "$path" && ! -L "$path" ]] || return 1
      chmod "${TX_DIRECTORY_MODE[i]}" "$path" || return 1
      chown "${TX_DIRECTORY_UID[i]}:${TX_DIRECTORY_GID[i]}" "$path" || return 1
    fi
  done
}

rollback() {
  systemctl disable --now disk-arcana-server >/dev/null 2>&1 || true
  rm -f -- "$LIVE_BINARY" "$LIVE_UNIT"
  systemctl daemon-reload >/dev/null 2>&1 || true
  restore_directories || return 1
  chmod "$TX_ENV_MODE" "$ENV_FILE" || return 1
  chown "$TX_ENV_UID:$TX_ENV_GID" "$ENV_FILE" || return 1
  if [[ "$TX_USER_EXISTED" == 0 ]] && service_user_exists; then
    if (( TEST_MODE )); then rm -f -- "$JOURNAL_DIR/test-user-exists"; else userdel disk-arcana || return 1; fi
  fi
  if [[ "$TX_GROUP_EXISTED" == 0 ]] && service_group_exists; then
    if (( TEST_MODE )); then rm -f -- "$JOURNAL_DIR/test-group-exists"; else groupdel disk-arcana || return 1; fi
  fi
}

recover_unfinished() {
  local recovered_state
  [[ -f "$JOURNAL" && ! -L "$JOURNAL" ]] || return 0
  load_journal || return 1
  recovered_state="$TX_STATE"
  if [[ "$TX_STATE" == COMMITTED ]]; then
    [[ -f "$LIVE_BINARY" && -f "$LIVE_UNIT" ]] || return 1
    [[ "$(sha256sum -- "$LIVE_BINARY" | awk '{print $1}')" == "$(sha256sum -- "$BINARY_PATH" | awk '{print $1}')" ]] || return 1
    [[ "$(sha256sum -- "$LIVE_UNIT" | awk '{print $1}')" == "$(sha256sum -- "$UNIT_PATH" | awk '{print $1}')" ]] || return 1
    systemctl is-active --quiet disk-arcana-server >/dev/null 2>&1 || return 1
    systemctl is-enabled --quiet disk-arcana-server >/dev/null 2>&1 || return 1
    health_body="$(curl --fail --silent --show-error --max-time 10 http://127.0.0.1:9446/health 2>/dev/null)" || return 1
    [[ "$(printf '%s' "$health_body" | tr -d '[:space:]')" == *'"status":"ok"'* ]] || return 1
    printf 'state=COMMITTED recovered=true\n'
    return 2
  fi
  rollback || return 1
  TX_STATE=FAILED_RECOVERED
  write_journal || return 1
  printf 'state=FAILED_RECOVERED recovered_from=%s\n' "$recovered_state"
  return 3
}

[[ "$(hostname 2>/dev/null)" == "$EXPECTED_HOSTNAME" ]] || die "hostname mismatch"

set +e
recover_unfinished
recovery_rc=$?
set -e
case "$recovery_rc" in
  0) ;;
  2) exit 0 ;;
  3) exit 1 ;;
  *) die "unfinished cold bootstrap could not be recovered" ;;
esac

for fixed_path in "$LIVE_BINARY" "$LIVE_UNIT" "$CONFIG_ROOT" "$DATA_ROOT" "$LOG_ROOT"; do
  assert_no_symlink_components "$fixed_path" || die "cold-bootstrap path has a symlink component"
done
[[ ! -e "$LIVE_BINARY" && ! -e "$LIVE_UNIT" ]] || die "install.sh is bootstrap-only; use disk-arcana-deploy-broker for updates"
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" && "$(stat -c '%a' "$ENV_FILE")" =~ ^(600|640)$ ]] || die "protected staging environment is absent or unsafe"
systemd-analyze verify "$UNIT_PATH" >/dev/null 2>&1 || die "bootstrap unit failed systemd verification"

if service_user_exists; then TX_USER_EXISTED=1; else TX_USER_EXISTED=0; fi
if service_group_exists; then TX_GROUP_EXISTED=1; else TX_GROUP_EXISTED=0; fi
TX_ENV_MODE="$(stat -c '%a' "$ENV_FILE")"
TX_ENV_UID="$(stat -c '%u' "$ENV_FILE")"
TX_ENV_GID="$(stat -c '%g' "$ENV_FILE")"
inventory_directories || die "cold-bootstrap directory inventory failed"
transition INVENTORIED || die "could not persist cold-bootstrap inventory"

if [[ "$TX_USER_EXISTED" == 0 ]]; then
  create_service_account || die "could not create service account"
fi
resolve_service_ids || die "could not resolve service account"
chown "$OWNER_UID:$SERVICE_GID" "$ENV_FILE" || { rollback || true; die "could not secure service environment"; }
chmod 0640 "$ENV_FILE" || { rollback || true; die "could not secure service environment"; }
transition ACCOUNT_READY || { rollback || true; die "could not persist account state"; }

ensure_directories || { rollback || true; die "could not create service directories"; }
transition DIRECTORIES_READY || { rollback || true; die "could not persist directory state"; }

tmp_binary="$(dirname "$LIVE_BINARY")/.disk-arcana-server.bootstrap.$$"
tmp_unit="$(dirname "$LIVE_UNIT")/.disk-arcana-server.service.bootstrap.$$"
install -o "$OWNER_UID" -g "$OWNER_GID" -m 0755 "$BINARY_PATH" "$tmp_binary"
install -o "$OWNER_UID" -g "$OWNER_GID" -m 0644 "$UNIT_PATH" "$tmp_unit"
fsync_path "$tmp_binary"; fsync_path "$tmp_unit"
mv -f -- "$tmp_binary" "$LIVE_BINARY"; mv -f -- "$tmp_unit" "$LIVE_UNIT"
fsync_path "$(dirname "$LIVE_BINARY")"; fsync_path "$(dirname "$LIVE_UNIT")"
transition FILES_INSTALLED || { rollback || true; die "could not persist installed state"; }

systemctl daemon-reload >/dev/null 2>&1 || { rollback || true; die "daemon reload failed"; }
systemctl enable --now disk-arcana-server >/dev/null 2>&1 || { rollback || true; die "cold service start failed"; }
transition SERVICE_ENABLED || { rollback || true; die "could not persist enabled state"; }

health_body="$(curl --fail --silent --show-error --max-time 10 http://127.0.0.1:9446/health 2>/dev/null)" || {
  rollback || true; die "cold service health failed"
}
[[ "$(printf '%s' "$health_body" | tr -d '[:space:]')" == *'"status":"ok"'* ]] || {
  rollback || true; die "cold service health failed"
}
systemctl is-active --quiet disk-arcana-server >/dev/null 2>&1 || { rollback || true; die "cold service is not active"; }
systemctl is-enabled --quiet disk-arcana-server >/dev/null 2>&1 || { rollback || true; die "cold service is not enabled"; }
transition HEALTH_VERIFIED || { rollback || true; die "could not persist verified state"; }

if (( TEST_MODE )) && [[ "${DISK_ARCANA_INSTALL_TEST_FAIL_AT:-}" == HEALTH_VERIFIED ]]; then
  rollback || true
  TX_STATE=FAILED_RECOVERED
  write_journal || true
  die "injected cold-bootstrap failure"
fi
transition COMMITTED || { rollback || true; die "could not commit cold bootstrap"; }
printf 'state=COMMITTED health=ok\n'
