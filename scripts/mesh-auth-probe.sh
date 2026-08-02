#!/usr/bin/env bash
# Read-only mesh server probe for arcana-agents :9543.
# Verifies TLS, health, AuthStore hydration evidence, ACL mac-operator entry.
# Does NOT mutate ACL or open RB-011.
set -euo pipefail

MESH_HOST="${MESH_HOST:-100.108.24.109}"
MESH_GRPC_PORT="${MESH_GRPC_PORT:-9543}"
MESH_HEALTH_PORT="${MESH_HEALTH_PORT:-9546}"
TLS_DIR="${TLS_DIR:-$HOME/.config/disk-arcana/tls}"
DB_PATH="${DB_PATH:-$HOME/.local/share/disk-arcana/disk.db}"
ACL_PATH="${ACL_PATH:-$HOME/.config/disk-arcana/disk-acl.yaml}"
TLS_DOMAIN="${TLS_DOMAIN:-arcana-dev}"

fail=0

echo "==> mesh TLS mTLS handshake (${MESH_HOST}:${MESH_GRPC_PORT})"
if timeout 5 openssl s_client -connect "${MESH_HOST}:${MESH_GRPC_PORT}" \
    -servername "$TLS_DOMAIN" \
    -cert "${TLS_DIR}/cert.pem" -key "${TLS_DIR}/key.pem" \
    -CAfile "${TLS_DIR}/ca.pem" </dev/null 2>&1 | grep -q 'Verify return code: 0'; then
    echo "PASS: mTLS verify 0"
else
    echo "FAIL: mTLS handshake"
    fail=1
fi

echo "==> health (${MESH_HOST}:${MESH_HEALTH_PORT})"
if curl -sf --max-time 5 "http://${MESH_HOST}:${MESH_HEALTH_PORT}/health"; then
    echo
    echo "PASS: health endpoint"
else
    echo "FAIL: health down"
    fail=1
fi

echo "==> ACL mac-operator entry"
if grep -q 'mac-operator' "$ACL_PATH" 2>/dev/null; then
    echo "PASS: mac-operator in ACL"
    grep -A2 'mac-operator' "$ACL_PATH" | head -3 || true
else
    echo "FAIL: mac-operator missing from ACL"
    fail=1
fi

echo "==> MetaDb nodes (mac-operator)"
if command -v python3 >/dev/null && [[ -f "$DB_PATH" ]]; then
    python3 - "$DB_PATH" <<'PY'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
row = con.execute(
    "SELECT node_id, display_name, platform, revoked FROM nodes WHERE node_id='mac-operator'"
).fetchone()
if row and row[3] == 0:
    print(f"PASS: mac-operator enrolled revoked={row[3]}")
else:
    print(f"FAIL: mac-operator row missing or revoked: {row}")
    sys.exit(1)
PY
else
    echo "SKIP: python3 or DB missing"
fi

echo "==> user unit active"
RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
if [[ -S "${RUNTIME_DIR}/systemd/private" ]]; then
    export XDG_RUNTIME_DIR="$RUNTIME_DIR"
fi
if systemctl --user is-active disk-arcana-server >/dev/null 2>&1; then
    echo "PASS: disk-arcana-server user unit active"
else
    echo "WARN: user unit not active (check system vs user scope)"
fi

exit "$fail"
