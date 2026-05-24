#!/usr/bin/env bash
# DISK-0006 R11 — Install Disk Arcana client daemon on Linux (systemd).
#
# Usage:
#     sudo ./scripts/install-linux.sh [--binary <path-to-disk>] [--config <path>]
#
# Side effects:
#     - Copies the `disk` binary to /usr/local/bin (mode 0755).
#     - Creates a system user `disk-arcana` (no shell, no home dir on $PATH).
#     - Provisions /etc/disk-arcana/ (root:disk-arcana 0750) and seeds disk.toml.
#     - Provisions /var/lib/disk-arcana/ + /var/log/disk-arcana/ owned by
#       disk-arcana:disk-arcana.
#     - Installs disk-arcana.service into /etc/systemd/system/ and enables
#       it (start-on-boot).
#     - Reloads systemd + starts the service.
#
# Reversible via scripts/uninstall-linux.sh (future R12).

set -euo pipefail

BINARY="${BINARY:-./target/release/disk}"
CONFIG_DIR="/etc/disk-arcana"
CONFIG_FILE="${CONFIG_DIR}/disk.toml"
STATE_DIR="/var/lib/disk-arcana"
LOG_DIR="/var/log/disk-arcana"
UNIT_SRC="$(cd "$(dirname "$0")/.." && pwd)/deploy/linux/disk-arcana.service"
UNIT_DST="/etc/systemd/system/disk-arcana.service"
SERVICE_USER="disk-arcana"

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

if [[ ! -f "$UNIT_SRC" ]]; then
    echo "error: systemd unit missing: $UNIT_SRC" >&2
    exit 1
fi

echo "==> installing $BINARY to /usr/local/bin/disk"
install -m 0755 "$BINARY" /usr/local/bin/disk

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    echo "==> creating system user $SERVICE_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

echo "==> provisioning $CONFIG_DIR"
install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
if [[ ! -f "$CONFIG_FILE" ]]; then
    if [[ -f disk.toml.example ]]; then
        install -m 0640 -o root -g "$SERVICE_USER" disk.toml.example "$CONFIG_FILE"
        echo "    seeded $CONFIG_FILE from disk.toml.example (edit before start)"
    else
        echo "    no disk.toml.example found — operator MUST create $CONFIG_FILE before start"
    fi
fi

echo "==> provisioning $STATE_DIR + $LOG_DIR (owner $SERVICE_USER)"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$LOG_DIR"

echo "==> installing systemd unit to $UNIT_DST"
install -m 0644 -o root -g root "$UNIT_SRC" "$UNIT_DST"

echo "==> reloading systemd + enabling + starting disk-arcana.service"
systemctl daemon-reload
systemctl enable disk-arcana.service
systemctl restart disk-arcana.service

echo "==> waiting for service to settle..."
for _ in $(seq 1 30); do
    if systemctl is-active --quiet disk-arcana.service; then
        if journalctl --no-pager -u disk-arcana --since "30 seconds ago" \
                | grep -q "listening on"; then
            echo "    OK — daemon is up:"
            journalctl --no-pager -u disk-arcana --since "30 seconds ago" \
                | grep "listening on" | tail -1
            echo
            echo "Done. Operator next steps:"
            echo "  1. Edit $CONFIG_FILE and run \`sudo systemctl restart disk-arcana\`"
            echo "  2. Verify status via \`curl -sf http://127.0.0.1:9444/status | jq .\`"
            echo "  3. Tail logs: \`journalctl -u disk-arcana -f\`"
            exit 0
        fi
    fi
    sleep 1
done

echo "warn: service did not log a 'listening' line within 30 s; current state:" >&2
systemctl status disk-arcana.service --no-pager || true
exit 1
