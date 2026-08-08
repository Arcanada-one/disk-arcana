#!/usr/bin/env bash
# DISK-0070: install a version-controlled share drop-in for the *user* server
# unit and verify every served share is declared.
#
# The manifest-bound release broker handles the system service. On
# arcana-agents the server runs as a user unit under
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
# The user that owns the user-scope unit. On arcana-agents the CI runner is a
# different user, so the owner cannot be assumed to be the caller.
UNIT_OWNER="${DISK_UNIT_OWNER:-dev}"
DROPIN_SRC="${DISK_DROPIN_SRC:-}"
DROPIN_DIR="${DISK_DROPIN_DIR:-}"
MODE="dry-run"

# Resolve a user's home without assuming `getent` exists (absent on macOS,
# where these scripts are edited and unit-tested).
owner_home_of() {
  local user="$1" home
  if command -v getent >/dev/null 2>&1; then
    home="$(getent passwd "$user" 2>/dev/null | cut -d: -f6)"
  fi
  if [[ -z "${home:-}" ]]; then
    home="$(eval printf '%s' "~$user" 2>/dev/null)"
    [[ "$home" == "~$user" ]] && home=""
  fi
  printf '%s' "${home:-}"
}

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

# The drop-in belongs to the unit owner's config tree, not the caller's.
if [[ -z "$DROPIN_DIR" ]]; then
  owner_home="$(owner_home_of "$UNIT_OWNER")"
  [[ -n "$owner_home" ]] || die "unknown unit owner '$UNIT_OWNER' (set DISK_UNIT_OWNER)"
  DROPIN_DIR="$owner_home/.config/systemd/user/${UNIT_NAME}.d"
fi

# --- contract: every served share must be declared -------------------------
# Read DISK_SHARE_ROOTS from the drop-in and DISK_SYNC_ROOT from the unit, then
# refuse a combination that leaves the sync-root share unwatched. This is the
# same predicate the server logs at startup (`sync_root_is_unwatched`), applied
# before the host is touched rather than after.
share_roots="$(sed -n 's|^Environment=DISK_SHARE_ROOTS=||p' "$DROPIN_SRC" | tail -1)"
[[ -n "$share_roots" ]] || die "$DROPIN_SRC declares no DISK_SHARE_ROOTS"

# Resolving DISK_SYNC_ROOT has to work from a session that does NOT own the
# unit: on arcana-agents the CI runner executes as `support-proof` while the
# server is a user unit of `dev`, so `systemctl --user` reaches the caller's own
# bus and never sees it. Try the live bus first, then read the unit file of the
# owning user directly. `%h` in the unit expands to that user's home.
resolve_sync_root() {
  local value
  value="$(systemctl --user show "$UNIT_NAME" -p Environment --value 2>/dev/null |
    tr ' ' '\n' | sed -n 's|^DISK_SYNC_ROOT=||p' | tail -1)"
  if [[ -n "$value" ]]; then
    printf '%s' "$value"
    return 0
  fi

  local owner_home unit_file
  owner_home="$(owner_home_of "$UNIT_OWNER")"
  [[ -n "$owner_home" ]] || return 1
  unit_file="$owner_home/.config/systemd/user/$UNIT_NAME"
  [[ -r "$unit_file" ]] || return 1

  value="$(sed -n 's|^Environment=DISK_SYNC_ROOT=||p' "$unit_file" | tail -1)"
  [[ -n "$value" ]] || return 1
  printf '%s' "${value//%h/$owner_home}"
}

# The drop-in may declare the expected sync root for hosts where the owner's
# home is unreadable to the caller (see the header of the shipped drop-in).
declared_sync_root="$(sed -n 's|^# *x-disk-expected-sync-root: *||p' "$DROPIN_SRC" | tail -1)"

live_sync_root="$(resolve_sync_root || true)"

sync_root="${DISK_SYNC_ROOT_OVERRIDE:-}"
if [[ -z "$sync_root" ]]; then
  sync_root="${live_sync_root:-$declared_sync_root}"
fi
[[ -n "$sync_root" ]] || die "could not determine DISK_SYNC_ROOT.
Neither the caller's user bus nor ${UNIT_OWNER}'s unit file provided it, and the
drop-in declares no 'x-disk-expected-sync-root:'. When running from a session
that does not own the unit (e.g. a CI runner under a different user), add that
line to the drop-in or pass DISK_SYNC_ROOT_OVERRIDE explicitly."

# A declared value must never diverge from reality unnoticed: when the live
# value IS reachable, they have to agree.
if [[ -n "$live_sync_root" && -n "$declared_sync_root" && "$live_sync_root" != "$declared_sync_root" ]]; then
  die "the drop-in's declared sync root does not match the running unit.
declared (x-disk-expected-sync-root): $declared_sync_root
live (from ${UNIT_OWNER}'s unit):      $live_sync_root
Fix the declaration rather than shipping a check against a stale path."
fi

if [[ -z "$live_sync_root" ]]; then
  log "note: live DISK_SYNC_ROOT unreachable from this session; using the value declared in the drop-in"
fi

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
      # A difference is the expected outcome of a dry-run, not an error, so the
      # non-zero exit status of `diff` must not fail the step.
      if diff -u "$dest" "$DROPIN_SRC"; then
        log "(installed copy is identical)"
      else
        log "(differs from the installed copy — shown above)"
      fi
    else
      log "(no installed copy yet)"
    fi
    log "Run with --install to apply."
    ;;
  install)
    # Writing into another user's config tree and restarting their unit needs
    # that user's own session; refuse loudly instead of half-applying.
    if [[ "$(id -un)" != "$UNIT_OWNER" ]]; then
      die "--install must run as '$UNIT_OWNER' (current user: $(id -un)).
The drop-in lives in that user's config tree and the restart needs their systemd
session; a foreign session cannot reach either."
    fi
    mkdir -p "$DROPIN_DIR"
    install -m 0644 "$DROPIN_SRC" "$dest"
    systemctl --user daemon-reload
    systemctl --user restart "$UNIT_NAME"
    log "installed and restarted $UNIT_NAME"
    ;;
  verify)
    if [[ "$(id -un)" != "$UNIT_OWNER" ]]; then
      die "--verify must run as '$UNIT_OWNER' (current user: $(id -un)) — the
loaded environment is only visible on that user's systemd bus."
    fi
    loaded="$(systemctl --user show "$UNIT_NAME" -p Environment --value 2>/dev/null |
      tr ' ' '\n' | sed -n 's|^DISK_SHARE_ROOTS=||p' | tail -1)"
    [[ "$loaded" == "$share_roots" ]] ||
      die "loaded DISK_SHARE_ROOTS does not match the drop-in.
loaded:  $loaded
drop-in: $share_roots"
    log "verify OK: loaded DISK_SHARE_ROOTS matches the drop-in"
    ;;
esac
