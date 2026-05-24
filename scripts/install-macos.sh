#!/usr/bin/env bash
# DISK-0006 R11 — Install Disk Arcana client daemon on macOS.
#
# Usage:
#     sudo ./scripts/install-macos.sh [--binary <path-to-disk>] [--config <path>]
#
# Side effects:
#     - Copies the `disk` binary to /usr/local/bin (mode 0755).
#     - Provisions /etc/disk-arcana/ (mode 0755) and copies disk.toml.example
#       as disk.toml if one isn't already present.
#     - Provisions /var/lib/disk-arcana/ and /var/log/disk-arcana/ (root:wheel 0755).
#     - Installs com.arcanada.disk-arcana.plist into /Library/LaunchDaemons/
#       (mode 0644, owner root:wheel — launchd refuses 0644+ on other modes).
#     - Loads the LaunchDaemon via `launchctl bootstrap system`.
#
# Reversible via scripts/uninstall-macos.sh (future R12).

set -euo pipefail

BINARY="${BINARY:-./target/release/disk}"
CONFIG_DIR="/etc/disk-arcana"
CONFIG_FILE="${CONFIG_DIR}/disk.toml"
STATE_DIR="/var/lib/disk-arcana"
LOG_DIR="/var/log/disk-arcana"
PLIST_SRC="$(cd "$(dirname "$0")/.." && pwd)/deploy/macos/com.arcanada.disk-arcana.plist"
PLIST_DST="/Library/LaunchDaemons/com.arcanada.disk-arcana.plist"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) BINARY="$2"; shift 2 ;;
        --config) CONFIG_FILE="$2"; CONFIG_DIR="$(dirname "$2")"; shift 2 ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

if [[ "$EUID" -ne 0 ]]; then
    echo "error: this script must run as root (sudo)" >&2
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    echo "error: binary not found or not executable: $BINARY" >&2
    echo "hint: run 'cargo build --release -p disk-cli' first" >&2
    exit 1
fi

if [[ ! -f "$PLIST_SRC" ]]; then
    echo "error: plist source missing: $PLIST_SRC" >&2
    exit 1
fi

echo "==> installing $BINARY to /usr/local/bin/disk"
install -m 0755 "$BINARY" /usr/local/bin/disk

echo "==> provisioning $CONFIG_DIR"
install -d -m 0755 -o root -g wheel "$CONFIG_DIR"
if [[ ! -f "$CONFIG_FILE" ]]; then
    if [[ -f disk.toml.example ]]; then
        install -m 0644 -o root -g wheel disk.toml.example "$CONFIG_FILE"
        echo "    seeded $CONFIG_FILE from disk.toml.example (edit before bootstrap)"
    else
        echo "    no disk.toml.example found — operator MUST create $CONFIG_FILE before bootstrap"
    fi
fi

echo "==> provisioning $STATE_DIR + $LOG_DIR"
install -d -m 0755 -o root -g wheel "$STATE_DIR"
install -d -m 0755 -o root -g wheel "$LOG_DIR"

echo "==> installing LaunchDaemon plist to $PLIST_DST"
install -m 0644 -o root -g wheel "$PLIST_SRC" "$PLIST_DST"

# launchctl bootstrap fails idempotently if the daemon is already loaded;
# bootout-then-bootstrap is the safe re-install dance.
if launchctl print system/com.arcanada.disk-arcana >/dev/null 2>&1; then
    echo "==> unloading existing LaunchDaemon (re-install)"
    launchctl bootout system "$PLIST_DST" || true
fi

echo "==> bootstrapping LaunchDaemon"
launchctl bootstrap system "$PLIST_DST"

echo "==> waiting for daemon to log a 'listening' line..."
for _ in $(seq 1 30); do
    if grep -q "listening on" "$LOG_DIR/disk-daemon.err.log" 2>/dev/null; then
        echo "    OK — daemon is up:"
        tail -1 "$LOG_DIR/disk-daemon.err.log"
        echo
        echo "Done. Operator next steps:"
        echo "  1. Edit $CONFIG_FILE and run \`sudo launchctl kickstart -k system/com.arcanada.disk-arcana\`"
        echo "  2. Verify status via \`curl -sf http://127.0.0.1:9444/status | jq .\`"
        exit 0
    fi
    sleep 1
done

echo "warn: daemon did not produce a 'listening' line within 30 s — check $LOG_DIR/disk-daemon.err.log" >&2
exit 1
