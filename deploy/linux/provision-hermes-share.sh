#!/usr/bin/env bash
# provision-hermes-share.sh — wire hermes-artefacts on arcana-agents mesh server.
#
# Run ON arcana-agents (100.108.24.109) as root or via sudo.
# Does NOT stop Mac bash MVP. Does NOT modify datarim-kb paths.
#
# Usage:
#   sudo ./provision-hermes-share.sh [--dry-run]
#
# Preconditions:
#   - disk-arcana-server running (:9543 mesh)
#   - /home/hermes/.hermes/cache populated (Hermes writer)
#   - DISK_DB_PATH + DISK_SYNC_ROOT in /etc/disk-arcana/env
#   - `disk` CLI built (or DISK_BIN=/path/to/disk)

set -euo pipefail

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
fi

ENV_FILE="${DISK_ENV_FILE:-/etc/disk-arcana/env}"
HERMES_SOURCE="${HERMES_CACHE_SOURCE:-/home/hermes/.hermes/cache}"
SHARE_MOUNT="${HERMES_SHARE_MOUNT:-/var/lib/disk-arcana/shares/hermes-artefacts}"
SHARE_NAME="${HERMES_SHARE_NAME:-hermes-artefacts}"
DISK_BIN="${DISK_BIN:-/usr/local/bin/disk}"

log() { printf '[provision-hermes] %s\n' "$*"; }
run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY + $*"
  else
    log "+ $*"
    "$@"
  fi
}

if [[ ! -d "$HERMES_SOURCE" ]]; then
  echo "ERROR: Hermes cache missing at $HERMES_SOURCE" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: env file missing: $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

: "${DISK_DB_PATH:?DISK_DB_PATH must be set in $ENV_FILE}"
: "${DISK_SYNC_ROOT:?DISK_SYNC_ROOT must be set in $ENV_FILE}"

run mkdir -p "$(dirname "$SHARE_MOUNT")"
if ! mountpoint -q "$SHARE_MOUNT" 2>/dev/null; then
  run mkdir -p "$SHARE_MOUNT"
  # Bind-mount keeps Hermes cache authoritative; disk-arcana reads the same tree.
  run mount --bind "$HERMES_SOURCE" "$SHARE_MOUNT"
fi

SHARE_ROOTS_LINE="${SHARE_NAME}:${SHARE_MOUNT}"
if grep -q '^DISK_SHARE_ROOTS=' "$ENV_FILE" 2>/dev/null; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY update DISK_SHARE_ROOTS in $ENV_FILE"
  else
    if grep -q "hermes-artefacts" "$ENV_FILE"; then
      log "DISK_SHARE_ROOTS already mentions hermes-artefacts — leaving env unchanged"
    else
      sed -i "s|^DISK_SHARE_ROOTS=.*|DISK_SHARE_ROOTS=${SHARE_ROOTS_LINE}|" "$ENV_FILE"
    fi
  fi
else
  run bash -c "printf '\n# R13 hermes-artefacts secondary root (DISK-0001)\nDISK_SHARE_ROOTS=%s\n' '$SHARE_ROOTS_LINE' >> '$ENV_FILE'"
fi

if [[ ! -x "$DISK_BIN" ]]; then
  echo "WARN: $DISK_BIN not found — skip MetaDb seed; run manually after build:" >&2
  echo "  disk import-state --from-rsync $SHARE_MOUNT --as-share $SHARE_NAME --db-path $DISK_DB_PATH --dry-run" >&2
else
  log "Seeding MetaDb (dry-run first)…"
  run "$DISK_BIN" import-state \
    --from-rsync "$SHARE_MOUNT" \
    --as-share "$SHARE_NAME" \
    --db-path "$DISK_DB_PATH" \
    --node-id "arcana-agents" \
    --dry-run
  run "$DISK_BIN" import-state \
    --from-rsync "$SHARE_MOUNT" \
    --as-share "$SHARE_NAME" \
    --db-path "$DISK_DB_PATH" \
    --node-id "arcana-agents"
fi

if systemctl is-active disk-arcana-server &>/dev/null; then
  run systemctl kill --signal=SIGHUP disk-arcana-server
  log "SIGHUP sent — server reloads env + ACL"
else
  log "WARN: disk-arcana-server not active via systemd — reload manually"
fi

log "Done. Verify:"
log "  mountpoint $SHARE_MOUNT"
log "  grep DISK_SHARE_ROOTS $ENV_FILE"
log "  sqlite3 $DISK_DB_PATH \"SELECT COUNT(*) FROM files WHERE vault_id='$SHARE_NAME';\""
