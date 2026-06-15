#!/usr/bin/env bash
# =============================================================================
# DEV-ONLY loopback bring-up for disk-arcana (local E2E gate).
#
# WARNING: This script sets DISK_USE_STUB_CA=1 and DISK_ACL_ALLOW_UNSIGNED=1.
# These flags disable the real Auth Arcana CA chain and GPG ACL verification.
# They MUST NEVER be used in production configs, deploy manifests, or committed
# disk.toml files. This script is for local development and CI smoke only.
# =============================================================================
#
# Usage:
#   ./scripts/dev-local-e2e.sh           # start server + daemon, tail /status
#   ./scripts/dev-local-e2e.sh --clean   # just remove /tmp/disk-local
#   ./scripts/dev-local-e2e.sh --stop    # kill any running dev-local processes
#
# The script is idempotent: running it twice cleans /tmp/disk-local first.
# Processes are tracked via /tmp/disk-local/pids and killed on EXIT.
# =============================================================================

set -euo pipefail

WORKDIR=/tmp/disk-local
VAULT_DIR="$WORKDIR/vault"
LOG_DIR="$WORKDIR/logs"
SERVER_PID_FILE="$WORKDIR/server.pid"
DAEMON_PID_FILE="$WORKDIR/daemon.pid"
PORT_FILE="$WORKDIR/daemon.port"

# ── Helper: find the release binary ─────────────────────────────────────────

find_bin() {
    local name="$1"
    local candidate
    # Prefer the binary in the target directory of this repo.
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
    for profile in release debug; do
        candidate="$REPO_ROOT/target/$profile/$name"
        if [[ -x "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    # Fall back to PATH.
    if command -v "$name" &>/dev/null; then
        command -v "$name"
        return 0
    fi
    echo "ERROR: $name not found; run 'cargo build --release' first" >&2
    return 1
}

# ── --clean / --stop shortcuts ───────────────────────────────────────────────

if [[ "${1:-}" == "--clean" ]]; then
    echo "Removing $WORKDIR ..."
    rm -rf "$WORKDIR"
    echo "Done."
    exit 0
fi

if [[ "${1:-}" == "--stop" ]]; then
    for pf in "$SERVER_PID_FILE" "$DAEMON_PID_FILE"; do
        if [[ -f "$pf" ]]; then
            pid="$(cat "$pf")"
            kill "$pid" 2>/dev/null && echo "Killed PID $pid" || true
        fi
    done
    exit 0
fi

# ── Locate binaries ──────────────────────────────────────────────────────────

SERVER_BIN="$(find_bin disk-arcana-server)"
CLIENT_BIN="$(find_bin disk)"

echo "server: $SERVER_BIN"
echo "client: $CLIENT_BIN"

# ── Idempotent clean ─────────────────────────────────────────────────────────

if [[ -d "$WORKDIR" ]]; then
    echo "Cleaning previous run at $WORKDIR ..."
    # Kill any previously tracked processes.
    for pf in "$SERVER_PID_FILE" "$DAEMON_PID_FILE"; do
        if [[ -f "$pf" ]]; then
            pid="$(cat "$pf")"
            kill "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$WORKDIR"
fi

mkdir -p "$WORKDIR" "$VAULT_DIR" "$LOG_DIR"

# ── Cleanup trap ─────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    echo "[dev-local] Shutting down ..."
    [[ -f "$SERVER_PID_FILE" ]] && kill "$(cat "$SERVER_PID_FILE")" 2>/dev/null || true
    [[ -f "$DAEMON_PID_FILE" ]] && kill "$(cat "$DAEMON_PID_FILE")" 2>/dev/null || true
    # Do NOT rm -rf $WORKDIR on EXIT so callers can inspect logs.
}
trap cleanup EXIT

# ── Step 1: Mint throwaway certs ─────────────────────────────────────────────

echo "[dev-local] Minting throwaway CA + server + node certs in $WORKDIR ..."

# CA
openssl genrsa -out "$WORKDIR/ca.key" 4096 2>/dev/null
openssl req -x509 -new -nodes \
    -key "$WORKDIR/ca.key" \
    -sha256 -days 365 \
    -out "$WORKDIR/ca.crt" \
    -subj "/CN=DiskLocalCA" 2>/dev/null

# Server leaf (signed by CA, SAN for localhost + 127.0.0.1)
openssl genrsa -out "$WORKDIR/server.key" 2048 2>/dev/null
openssl req -new \
    -key "$WORKDIR/server.key" \
    -out "$WORKDIR/server.csr" \
    -subj "/CN=localhost" 2>/dev/null
openssl x509 -req \
    -in "$WORKDIR/server.csr" \
    -CA "$WORKDIR/ca.crt" \
    -CAkey "$WORKDIR/ca.key" \
    -CAcreateserial \
    -out "$WORKDIR/server.crt" \
    -days 365 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\n") 2>/dev/null

# Node leaf (signed by CA)
openssl genrsa -out "$WORKDIR/node.key" 2048 2>/dev/null
openssl req -new \
    -key "$WORKDIR/node.key" \
    -out "$WORKDIR/node.csr" \
    -subj "/CN=local-test-node" 2>/dev/null
openssl x509 -req \
    -in "$WORKDIR/node.csr" \
    -CA "$WORKDIR/ca.crt" \
    -CAkey "$WORKDIR/ca.key" \
    -CAcreateserial \
    -out "$WORKDIR/node.crt" \
    -days 365 2>/dev/null

chmod 600 "$WORKDIR"/*.key
echo "[dev-local] Certs minted."

# ── Step 2: Write ACL ────────────────────────────────────────────────────────

NODE_FP="$(openssl x509 -in "$WORKDIR/node.crt" -noout -fingerprint -sha256 2>/dev/null \
    | cut -d= -f2 | tr -d ':')"

cat > "$WORKDIR/acl.yaml" <<EOF
version: 0
nodes:
  - cert_fingerprint_sha256: "${NODE_FP}"
    roles:
      - share: "test-share"
        direction: distribute
EOF
echo "[dev-local] ACL written (fingerprint: $NODE_FP)."

# ── Step 3: Write disk.toml ──────────────────────────────────────────────────

cat > "$WORKDIR/disk.toml" <<EOF
[node]
id = "local-test"

[node.default]
intended_direction = "bidirectional"

[server]
address = "127.0.0.1:9443"
client_cert = "$WORKDIR/node.crt"
client_key  = "$WORKDIR/node.key"
server_ca   = "$WORKDIR/ca.crt"

[[share]]
name = "test-share"
path = "$VAULT_DIR"
EOF
echo "[dev-local] disk.toml written."

# ── Step 4: Start disk-arcana-server ─────────────────────────────────────────

echo "[dev-local] Starting disk-arcana-server ..."
# DEV-ONLY flags: DISK_USE_STUB_CA=1 + DISK_ACL_ALLOW_UNSIGNED=1.
# NEVER apply these in production environments.
env \
    DISK_BIND_ADDR=127.0.0.1:9443 \
    DISK_ENROLLMENT_BIND_ADDR=127.0.0.1:9445 \
    DISK_HEALTH_BIND_ADDR=127.0.0.1:9446 \
    DISK_DB_PATH="$WORKDIR/server.sqlite" \
    DISK_SYNC_ROOT="$WORKDIR/server-root" \
    DISK_TLS_CERT_PATH="$WORKDIR/server.crt" \
    DISK_TLS_KEY_PATH="$WORKDIR/server.key" \
    DISK_TLS_CA_PATH="$WORKDIR/ca.crt" \
    DISK_ACL_YAML_PATH="$WORKDIR/acl.yaml" \
    DISK_USE_STUB_CA=1 \
    DISK_ACL_ALLOW_UNSIGNED=1 \
    RUST_LOG=info \
    "$SERVER_BIN" \
    > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$SERVER_PID_FILE"
echo "[dev-local] server PID=$SERVER_PID"

# Wait up to 10 s for the server health endpoint.
echo "[dev-local] Waiting for server health ..."
for i in $(seq 1 20); do
    if curl -sf "http://127.0.0.1:9446/health" >/dev/null 2>&1; then
        echo "[dev-local] Server is up."
        break
    fi
    sleep 0.5
    if [[ $i -eq 20 ]]; then
        echo "ERROR: server did not respond within 10 s." >&2
        cat "$LOG_DIR/server.log" >&2
        exit 1
    fi
done

# ── Step 5: Start disk daemon ────────────────────────────────────────────────

mkdir -p "$WORKDIR/state"
echo "[dev-local] Starting disk daemon ..."
"$CLIENT_BIN" daemon start \
    --foreground \
    --config "$WORKDIR/disk.toml" \
    --status-bind 127.0.0.1:9444 \
    --state-dir "$WORKDIR/state" \
    > "$LOG_DIR/daemon.log" 2>&1 &
DAEMON_PID=$!
echo "$DAEMON_PID" > "$DAEMON_PID_FILE"
echo 9444 > "$PORT_FILE"
echo "[dev-local] daemon PID=$DAEMON_PID"

# ── Step 6: Poll /status until 200 ───────────────────────────────────────────

echo "[dev-local] Waiting for daemon /status ..."
for i in $(seq 1 30); do
    STATUS_OUT="$(curl -sf "http://127.0.0.1:9444/status" 2>/dev/null || true)"
    if [[ -n "$STATUS_OUT" ]]; then
        echo "[dev-local] /status is up:"
        echo "$STATUS_OUT" | python3 -m json.tool 2>/dev/null || echo "$STATUS_OUT"
        echo ""
        echo "[dev-local] PASS — daemon is running. Vault: $VAULT_DIR"
        echo "[dev-local] Tip: touch or edit files in $VAULT_DIR to trigger a sync cycle."
        echo "[dev-local] Tip: poll http://127.0.0.1:9444/status to observe state transitions."
        echo ""
        echo "Press Ctrl-C to shut down."
        # Keep script alive so the trap can clean up.
        wait "$SERVER_PID" "$DAEMON_PID" 2>/dev/null || true
        exit 0
    fi
    sleep 1
    if [[ $i -eq 30 ]]; then
        echo "ERROR: daemon did not respond within 30 s." >&2
        cat "$LOG_DIR/daemon.log" >&2
        exit 1
    fi
done
