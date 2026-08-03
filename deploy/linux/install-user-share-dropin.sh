#!/usr/bin/env bash
# DISK-0070: install a version-controlled share drop-in for the *user* server
# unit and verify every served share is declared.
#
# The existing scripts/install-systemd-unit.sh handles system units under
# /etc/systemd/system. On arcana-agents the server runs as a user unit under
# `dev`, and its share configuration lived only in a hand-made drop-in with no
# source in the repo. This script closes that gap: the drop-in comes from
# deploy/linux/user-dropins/, and the check below refuses a configuration that
# would leave DISK_SYNC_ROOT unwatched.
#
# Dry-run is the default; installing is an explicit opt-in.
#
#   install-user-share-dropin.sh [--dropin FILE] [--install] [--verify]

set -euo pipefail

UNIT_NAME="disk-arcana-server.service"
DROPIN_SRC="${DISK_DROPIN_SRC:-}"
DROPIN_DIR="${DISK_DROPIN_DIR:-$HOME/.config/systemd/user/${UNIT_NAME}.d}"
MODE="dry-run"

log() { printf '%s\n' "$*"; }
die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dropin)
      DROPIN_SRC="${2:?--dropin needs a path}"
      shift 2
      ;;
    --install)
      MODE="install"
      shift
      ;;
    --verify)
      MODE="verify"
      shift
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "$DROPIN_SRC" ]]; then
  DROPIN_SRC="$script_dir/user-dropins/arcana-agents-shares.conf"
fi
[[ -f "$DROPIN_SRC" ]] || die "drop-in source not found: $DROPIN_SRC"

# --- contract: every served share must be declared -------------------------
# Read DISK_SHARE_ROOTS from the drop-in and DISK_SYNC_ROOT from the unit, then
# refuse a combination that leaves the sync-root share unwatched. This is the
# same predicate the server logs at startup (`sync_root_is_unwatched`), applied
# before the host is touched rather than after.
share_roots="$(sed -n 's|^Environment=DISK_SHARE_ROOTS=||p' "$DROPIN_SRC" | tail -1)"
[[ -n "$share_roots" ]] || die "$DROPIN_SRC declares no DISK_SHARE_ROOTS"

sync_root="${DISK_SYNC_ROOT_OVERRIDE:-}"
if [[ -z "$sync_root" ]]; then
  sync_root="$(systemctl --user show "$UNIT_NAME" -p Environment --value 2>/dev/null |
    tr ' ' '\n' | sed -n 's|^DISK_SYNC_ROOT=||p' | tail -1)"
fi
[[ -n "$sync_root" ]] || die "could not determine DISK_SYNC_ROOT (set DISK_SYNC_ROOT_OVERRIDE to check offline)"

covered=0
IFS=',' read -r -a entries <<<"$share_roots"
for entry in "${entries[@]}"; do
  entry="${entry## }"
  [[ "$entry" == *:/* ]] || die "malformed entry '$entry' (want share:/absolute/path)"
  if [[ "${entry#*:}" == "$sync_root" ]]; then
    covered=1
  fi
done

if [[ "$covered" -ne 1 ]]; then
  die "DISK_SYNC_ROOT ($sync_root) is not among the declared share roots.
A share served through the sync-root fallback is read but never watched, so its
changes never reach clients while both ends report success (DISK-0070).
Declared: $share_roots"
fi

log "contract OK: ${#entries[@]} shares declared, DISK_SYNC_ROOT covered ($sync_root)"

dest="$DROPIN_DIR/$(basename "$DROPIN_SRC")"

case "$MODE" in
  dry-run)
    log "--- would install: $DROPIN_SRC -> $dest"
    if [[ -f "$dest" ]]; then
      diff -u "$dest" "$DROPIN_SRC" && log "(installed copy is identical)"
    else
      log "(no installed copy yet)"
    fi
    log "Run with --install to apply."
    ;;
  install)
    mkdir -p "$DROPIN_DIR"
    install -m 0644 "$DROPIN_SRC" "$dest"
    systemctl --user daemon-reload
    systemctl --user restart "$UNIT_NAME"
    log "installed and restarted $UNIT_NAME"
    ;;
  verify)
    loaded="$(systemctl --user show "$UNIT_NAME" -p Environment --value 2>/dev/null |
      tr ' ' '\n' | sed -n 's|^DISK_SHARE_ROOTS=||p' | tail -1)"
    [[ "$loaded" == "$share_roots" ]] ||
      die "loaded DISK_SHARE_ROOTS does not match the drop-in.
loaded:  $loaded
drop-in: $share_roots"
    log "verify OK: loaded DISK_SHARE_ROOTS matches the drop-in"
    ;;
esac
