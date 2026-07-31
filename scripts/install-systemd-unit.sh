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
TARGET_UNIT="/etc/systemd/system/$UNIT_NAME"
HEALTH_URL="http://127.0.0.1:9446/health"

# Expected loaded values. systemd normalises StartLimitIntervalSec=120s to
# "2min" in `systemctl show` output.
EXPECT_INTERVAL="2min"
EXPECT_BURST="5"

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  if sudo -n true 2>/dev/null; then
    SUDO="sudo -n"
  else
    printf 'ERROR: not root and no non-interactive sudo available\n' >&2
    exit 1
  fi
fi

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
  tgt_sum="$($SUDO sha256sum "$TARGET_UNIT" | awk '{print $1}')"
  printf 'repo      sha256=%s\n' "$src_sum"
  printf 'installed sha256=%s\n' "$tgt_sum"

  if [[ "$src_sum" == "$tgt_sum" ]]; then
    printf 'IDENTICAL — no unit change required\n'
    return 0
  fi

  printf '\n--- installed %s\n+++ repo %s\n' "$TARGET_UNIT" "$SOURCE_UNIT"
  # The unit carries no secrets (those live in the EnvironmentFile), so the
  # full diff is safe to print into a job log.
  $SUDO cat "$TARGET_UNIT" >/tmp/disk-arcana-installed-unit.$$
  diff -u /tmp/disk-arcana-installed-unit.$$ "$SOURCE_UNIT" || true
  rm -f /tmp/disk-arcana-installed-unit.$$
}

health_ok() {
  local body status
  for _ in $(seq 1 12); do
    if body="$(curl -sf --max-time 10 "$HEALTH_URL" 2>/dev/null)"; then
      status="$(jq -r '.status // empty' <<<"$body" 2>/dev/null || true)"
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

do_install() {
  local backup=""

  show_diff

  if [[ -f "$TARGET_UNIT" ]]; then
    backup="${TARGET_UNIT}.bak-$(date -u +%Y%m%dT%H%M%SZ)"
    $SUDO cp -a "$TARGET_UNIT" "$backup"
    printf 'backup: %s\n' "$backup"
  fi

  $SUDO install -o root -g root -m 0644 "$SOURCE_UNIT" "$TARGET_UNIT"
  $SUDO systemctl daemon-reload
  printf 'installed %s and reloaded systemd\n' "$TARGET_UNIT"

  $SUDO systemctl restart "$UNIT_NAME"

  if health_ok; then
    printf 'health OK after restart\n'
  else
    printf 'health check FAILED after restart — rolling back\n' >&2
    if [[ -n "$backup" ]]; then
      $SUDO cp -a "$backup" "$TARGET_UNIT"
      $SUDO systemctl daemon-reload
      $SUDO systemctl restart "$UNIT_NAME"
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
