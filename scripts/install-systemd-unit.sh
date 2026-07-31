#!/usr/bin/env bash
# INFRA-0370: deliver deploy/linux/disk-arcana-server.service to a host.
#
# The release pipeline installs the *binary* only, so a corrected unit file in
# the repo never reached any host — the restart-limit fix would have stayed
# inert. This script is the delivery step.
#
#   --dry-run   diff the repo unit against the installed one; change nothing
#   --install   back up, install, daemon-reload, restart, health-check, and
#               roll back to the backup if the service does not come healthy
#   --verify    assert the *loaded* restart policy matches the repo unit
#
# Safe to re-run: --install is a no-op restart when the files already match.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

UNIT_NAME="disk-arcana-server.service"
SOURCE_UNIT="$REPO_ROOT/deploy/linux/$UNIT_NAME"
# Overridable so the diff/backup/rollback logic can be exercised against a
# throwaway directory in tests. Production runs leave these unset.
TARGET_DIR="${DISK_ARCANA_UNIT_DIR:-/etc/systemd/system}"
TARGET_UNIT="$TARGET_DIR/$UNIT_NAME"
HEALTH_URL="${DISK_ARCANA_HEALTH_URL:-http://127.0.0.1:9446/health}"

# Expected loaded values. systemd normalises StartLimitIntervalSec=120s to
# "2min" in `systemctl show` output.
EXPECT_INTERVAL="2min"
EXPECT_BURST="5"

BROKER="/usr/local/sbin/disk-arcana-install-unit"
SUDO=""
if [[ -n "${DISK_ARCANA_UNIT_DIR:-}" ]]; then
  # Test mode: writing into a throwaway directory we already own.
  :
elif [[ "$(id -u)" -eq 0 ]]; then
  :
elif sudo -n true 2>/dev/null; then
  SUDO="sudo -n"
fi

# ci-runner on arcana-prod has command-scoped sudo (not blanket `sudo -n true`).
# Read-only paths and systemctl queries work without sudo; writes go through the
# fixed-path broker when it has been bootstrapped on the host.
as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif [[ -n "$SUDO" ]]; then
    $SUDO "$@"
  else
    printf 'ERROR: need root for: %s\n' "$*" >&2
  fi
}

read_target() {
  if [[ -r "$TARGET_UNIT" ]]; then
    cat "$TARGET_UNIT"
  else
    as_root cat "$TARGET_UNIT"
  fi
}

sha256_target() {
  if [[ -r "$TARGET_UNIT" ]]; then
    sha256sum "$TARGET_UNIT" | awk '{print $1}'
  else
    as_root sha256sum "$TARGET_UNIT" | awk '{print $1}'
  fi
}

broker_install() {
  local expected_sha
  expected_sha="$(sha256sum "$SOURCE_UNIT" | awk '{print $1}')"
  if [[ ! -x "$BROKER" ]]; then
    printf 'ERROR: %s missing — bootstrap with deploy/linux/install-disk-arcana-install-unit-broker.sh (root)\n' \
      "$BROKER" >&2
    return 1
  fi
  sudo -n "$BROKER" --install "$expected_sha" "$REPO_ROOT"
}

if [[ ! -f "$SOURCE_UNIT" ]]; then
  printf 'ERROR: source unit missing: %s\n' "$SOURCE_UNIT" >&2
  exit 1
fi

show_diff() {
  if [[ ! -f "$TARGET_UNIT" ]]; then
    printf 'installed unit ABSENT at %s — install would create it\n' "$TARGET_UNIT"
    return 0
  fi

  local src_sum tgt_sum
  src_sum="$(sha256sum "$SOURCE_UNIT" | awk '{print $1}')"
  tgt_sum="$(sha256_target)"
  printf 'repo      sha256=%s\n' "$src_sum"
  printf 'installed sha256=%s\n' "$tgt_sum"

  if [[ "$src_sum" == "$tgt_sum" ]]; then
    printf 'IDENTICAL — no unit change required\n'
    return 0
  fi

  printf '\n--- installed %s\n+++ repo %s\n' "$TARGET_UNIT" "$SOURCE_UNIT"
  # The unit carries no secrets (those live in the EnvironmentFile), so the
  # full diff is safe to print into a job log.
  read_target >/tmp/disk-arcana-installed-unit.$$
  diff -u /tmp/disk-arcana-installed-unit.$$ "$SOURCE_UNIT" || true
  rm -f /tmp/disk-arcana-installed-unit.$$
}

health_ok() {
  local body status
  parse_health_status() {
    local payload="$1"
    if command -v jq >/dev/null 2>&1; then
      jq -r '.status // empty' <<<"$payload" 2>/dev/null || true
      return
    fi
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' <<<"$payload" 2>/dev/null || true
  }
  if [[ "$HEALTH_URL" == file://* ]]; then
    local path="${HEALTH_URL#file://}"
    for _ in $(seq 1 "${DISK_ARCANA_HEALTH_RETRIES:-12}"); do
      if [[ -r "$path" ]] && body="$(<"$path")"; then
        status="$(parse_health_status "$body")"
        if [[ "$status" == "ok" ]]; then
          printf '%s\n' "$body"
          return 0
        fi
      fi
      sleep 5
    done
    return 1
  fi
  for _ in $(seq 1 "${DISK_ARCANA_HEALTH_RETRIES:-12}"); do
    if body="$(curl -sf --max-time 10 "$HEALTH_URL" 2>/dev/null)"; then
      status="$(parse_health_status "$body")"
      if [[ "$status" == "ok" ]]; then
        printf '%s\n' "$body"
        return 0
      fi
    fi
    sleep 5
  done
  return 1
}

verify_loaded() {
  local interval burst restart
  if [[ -n "${DISK_ARCANA_UNIT_DIR:-}" ]]; then
    printf '(test mode) skipping loaded-policy verification\n'
    return 0
  fi
  interval="$(systemctl show "$UNIT_NAME" -p StartLimitIntervalUSec --value)"
  burst="$(systemctl show "$UNIT_NAME" -p StartLimitBurst --value)"
  restart="$(systemctl show "$UNIT_NAME" -p Restart --value)"

  printf 'loaded StartLimitIntervalUSec=%s StartLimitBurst=%s Restart=%s\n' \
    "$interval" "$burst" "$restart"

  local bad=0
  [[ "$interval" == "$EXPECT_INTERVAL" ]] || {
    printf 'FAIL StartLimitIntervalUSec=%s expected %s\n' "$interval" "$EXPECT_INTERVAL" >&2
    bad=1
  }
  [[ "$burst" == "$EXPECT_BURST" ]] || {
    printf 'FAIL StartLimitBurst=%s expected %s\n' "$burst" "$EXPECT_BURST" >&2
    bad=1
  }
  return "$bad"
}

# systemctl wrapper — a no-op in test mode, where there is no live unit.
# On arcana-prod the runner may restart disk-arcana-server without sudo; reload
# still requires root (broker or scoped sudo).
sd() {
  if [[ -n "${DISK_ARCANA_UNIT_DIR:-}" ]]; then
    printf '(test mode) skipping: systemctl %s\n' "$*"
    return 0
  fi
  if systemctl "$@" 2>/dev/null; then
    return 0
  fi
  as_root systemctl "$@"
}

install_unit_file() {
  if [[ -n "${DISK_ARCANA_UNIT_DIR:-}" ]]; then
    install -m 0644 "$SOURCE_UNIT" "$TARGET_UNIT"
  else
    as_root install -o root -g root -m 0644 "$SOURCE_UNIT" "$TARGET_UNIT"
  fi
}

do_install() {
  show_diff

  if [[ -n "${DISK_ARCANA_UNIT_DIR:-}" ]]; then
    local backup=""
    if [[ -f "$TARGET_UNIT" ]]; then
      backup="${TARGET_UNIT}.bak-$(date -u +%Y%m%dT%H%M%SZ)"
      cp -a "$TARGET_UNIT" "$backup"
      printf 'backup: %s\n' "$backup"
    fi
    install_unit_file
    sd daemon-reload
    printf 'installed %s and reloaded systemd\n' "$TARGET_UNIT"
    sd restart "$UNIT_NAME"
    if health_ok; then
      printf 'health OK after restart\n'
    else
      printf 'health check FAILED after restart — rolling back\n' >&2
      if [[ -n "$backup" ]]; then
        cp -a "$backup" "$TARGET_UNIT"
        sd daemon-reload
        sd restart "$UNIT_NAME"
      fi
      exit 1
    fi
    verify_loaded
    return
  fi

  if [[ "$(id -u)" -ne 0 && -z "$SUDO" ]]; then
    broker_install
    return
  fi

  local backup=""
  if [[ -f "$TARGET_UNIT" ]]; then
    backup="${TARGET_UNIT}.bak-$(date -u +%Y%m%dT%H%M%SZ)"
    as_root cp -a "$TARGET_UNIT" "$backup"
    printf 'backup: %s\n' "$backup"
  fi

  install_unit_file
  sd daemon-reload
  printf 'installed %s and reloaded systemd\n' "$TARGET_UNIT"
  sd restart "$UNIT_NAME"

  if health_ok; then
    printf 'health OK after restart\n'
  else
    printf 'health check FAILED after restart — rolling back\n' >&2
    if [[ -n "$backup" ]]; then
      as_root cp -a "$backup" "$TARGET_UNIT"
      sd daemon-reload
      sd restart "$UNIT_NAME"
      if health_ok; then
        printf 'rolled back to %s; service healthy again\n' "$backup" >&2
      else
        printf 'ROLLBACK DID NOT RESTORE HEALTH — manual intervention needed\n' >&2
      fi
    else
      printf 'no previous unit to roll back to\n' >&2
    fi
    exit 1
  fi

  verify_loaded
}

case "${1:---dry-run}" in
  --dry-run)
    show_diff
    printf '\n(dry run — nothing changed)\n'
    ;;
  --install)
    do_install
    ;;
  --verify)
    verify_loaded
    ;;
  *)
    printf 'usage: %s [--dry-run|--install|--verify]\n' "$0" >&2
    exit 2
    ;;
esac
