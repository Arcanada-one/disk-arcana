#!/usr/bin/env bash
# install.sh — Disk Arcana server install/update script for Linux.
#
# Usage:
#   sudo ./install.sh [--binary <path>] [--root <root>] [--no-systemd]
#
# Options:
#   --binary <path>   Path to compiled disk-arcana-server binary.
#                     Default: ../../target/x86_64-unknown-linux-gnu/release/disk-arcana-server
#   --root <path>     Filesystem root prefix (for testing). Default: /
#   --no-systemd      Skip systemctl commands (useful in containers/CI).
#
# What this does:
#   1. Creates system user disk-arcana (no login shell, no home).
#   2. Creates /etc/disk-arcana/, /var/lib/disk-arcana/, /var/log/disk-arcana/.
#   3. Copies binary to /usr/local/bin/disk-arcana-server.
#   4. Installs the systemd unit file to /etc/systemd/system/.
#   5. Optionally reloads systemd and enables/starts the service.
#
# Rollback: the previous binary (if present) is preserved as
#   /usr/local/bin/disk-arcana-server.prev

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- Defaults ----
BINARY_PATH="${SCRIPT_DIR}/../../target/x86_64-unknown-linux-gnu/release/disk-arcana-server"
ROOT="/"
NO_SYSTEMD=0

# ---- Argument parsing ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)  BINARY_PATH="$2"; shift 2 ;;
        --root)    ROOT="$2"; shift 2 ;;
        --no-systemd) NO_SYSTEMD=1; shift ;;
        -h|--help)
            sed -n '2,/^# What this does/p' "$0"
            exit 0
            ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# Strip trailing slash from ROOT (unless it's bare /).
ROOT="${ROOT%/}"

# ---- Helpers ----
log() { echo "[install] $*"; }
run() { log "+ $*"; "$@"; }

# ---- 1. System user ----
if ! id disk-arcana &>/dev/null; then
    log "Creating system user disk-arcana"
    run useradd --system --no-create-home --shell /usr/sbin/nologin disk-arcana
else
    log "User disk-arcana already exists"
fi

# ---- 2. Directories ----
for dir in \
    "${ROOT}/etc/disk-arcana" \
    "${ROOT}/etc/disk-arcana/tls" \
    "${ROOT}/etc/disk-arcana/gpg" \
    "${ROOT}/var/lib/disk-arcana" \
    "${ROOT}/var/log/disk-arcana"; do
    if [[ ! -d "$dir" ]]; then
        run mkdir -p "$dir"
    fi
done

run chown root:disk-arcana "${ROOT}/etc/disk-arcana"
run chmod 750              "${ROOT}/etc/disk-arcana"
run chown root:disk-arcana "${ROOT}/etc/disk-arcana/tls"
run chmod 750              "${ROOT}/etc/disk-arcana/tls"
run chown root:disk-arcana "${ROOT}/etc/disk-arcana/gpg"
run chmod 700              "${ROOT}/etc/disk-arcana/gpg"
run chown disk-arcana:disk-arcana "${ROOT}/var/lib/disk-arcana"
run chmod 750                     "${ROOT}/var/lib/disk-arcana"
run chown disk-arcana:disk-arcana "${ROOT}/var/log/disk-arcana"
run chmod 750                     "${ROOT}/var/log/disk-arcana"

# ---- 3. Binary ----
BIN_DEST="${ROOT}/usr/local/bin/disk-arcana-server"
run mkdir -p "${ROOT}/usr/local/bin"

if [[ -f "$BIN_DEST" ]]; then
    log "Preserving previous binary as ${BIN_DEST}.prev"
    run cp "$BIN_DEST" "${BIN_DEST}.prev"
fi

log "Installing binary from ${BINARY_PATH}"
if [[ ! -f "$BINARY_PATH" ]]; then
    echo "ERROR: binary not found at ${BINARY_PATH}" >&2
    exit 1
fi
run cp "$BINARY_PATH" "$BIN_DEST"
run chmod 755 "$BIN_DEST"
run chown root:root "$BIN_DEST"

# ---- 4. Systemd unit ----
UNIT_SRC="${SCRIPT_DIR}/disk-arcana-server.service"
UNIT_DEST="${ROOT}/etc/systemd/system/disk-arcana-server.service"

if [[ -f "$UNIT_SRC" ]]; then
    run cp "$UNIT_SRC" "$UNIT_DEST"
    run chmod 644 "$UNIT_DEST"
    run chown root:root "$UNIT_DEST"
else
    log "WARNING: unit file not found at ${UNIT_SRC}, skipping systemd setup"
    NO_SYSTEMD=1
fi

# ---- 5. Systemd reload ----
if [[ "$NO_SYSTEMD" -eq 0 ]]; then
    run systemctl daemon-reload
    run systemctl enable disk-arcana-server
    log "Service enabled. Start with: systemctl start disk-arcana-server"
else
    log "Skipping systemctl (--no-systemd or unit file missing)"
fi

log "Installation complete."
