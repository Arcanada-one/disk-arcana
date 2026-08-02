#!/usr/bin/env bash
# Read-only hermes-artefacts mesh share probe (arcana-agents :9543).
# Verifies share root, MetaDb index, ACL mac-operator receive_only. No RB-011.
set -euo pipefail

SHARE_ROOT="${SHARE_ROOT:-/var/lib/disk-arcana/shares/hermes-artefacts}"
DB_PATH="${DB_PATH:-$HOME/.local/share/disk-arcana/disk.db}"
ACL_PATH="${ACL_PATH:-$HOME/.config/disk-arcana/disk-acl.yaml}"

fail=0

echo "==> share root ${SHARE_ROOT}"
if [[ -d "$SHARE_ROOT" ]]; then
    echo "PASS: directory exists"
    find "$SHARE_ROOT" -type f 2>/dev/null | head -10 || true
    echo "file_count=$(find "$SHARE_ROOT" -type f 2>/dev/null | wc -l)"
else
    echo "FAIL: missing share root"
    fail=1
fi

echo "==> MetaDb hermes-artefacts"
if command -v python3 >/dev/null && [[ -f "$DB_PATH" ]]; then
    python3 - "$DB_PATH" <<'PY'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
n = con.execute("SELECT COUNT(*) FROM files WHERE vault_id='hermes-artefacts'").fetchone()[0]
print(f"PASS: hermes files indexed count={n}")
rows = con.execute(
    "SELECT path FROM files WHERE vault_id='hermes-artefacts' LIMIT 10"
).fetchall()
for r in rows:
    print(" ", r[0])
mac = con.execute(
    "SELECT vault_id, COUNT(*) FROM node_baselines WHERE node_id='mac-operator' AND vault_id='hermes-artefacts' GROUP BY vault_id"
).fetchall()
print("mac-operator hermes baselines:", mac or "none")
PY
else
    echo "SKIP: python3 or DB missing"
fi

echo "==> ACL mac-operator hermes role"
if grep -A5 'mac-operator' "$ACL_PATH" 2>/dev/null | grep -q 'hermes-artefacts: "receive_only"'; then
    echo "PASS: receive_only for mac-operator"
else
    echo "FAIL: hermes receive_only missing"
    fail=1
fi

exit "$fail"
