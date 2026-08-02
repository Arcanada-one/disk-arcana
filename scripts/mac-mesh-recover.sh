#!/usr/bin/env bash
# Mac mesh client recovery (DISK-0067/0069) — run on operator Mac in gui session.
# Read-only checks + optional kickstart + soak poll for hermes-artefacts.
# Does NOT open RB-011 or rewrite ACL.
set -euo pipefail

MESH_HOST="${MESH_HOST:-100.108.24.109}"
MESH_PORT="${MESH_PORT:-9543}"
TLS_DOMAIN="${TLS_DOMAIN:-arcana-dev}"
CONFIG="${DISK_CONFIG:-$HOME/.config/disk-arcana/disk.toml}"
TLS_DIR="${DISK_TLS_DIR:-$HOME/.config/disk-arcana/tls}"
STATUS_URL="${DISK_STATUS_URL:-http://127.0.0.1:9444/status}"
SYNC_URL="${DISK_SYNC_URL:-http://127.0.0.1:9444/sync}"
HERMES_PATH="${HERMES_PATH:-$HOME/arcanada/data/hermes}"
LABEL="gui/$(id -u)/com.arcanada.disk-arcana"
DO_KICKSTART="${DO_KICKSTART:-0}"
SOAK_SECONDS="${SOAK_SECONDS:-90}"

fail=0

echo "==> disk.toml server target"
if [[ -f "$CONFIG" ]]; then
    grep -E 'address|tls_domain|node_id|name = "hermes' "$CONFIG" || true
    if grep -q "${MESH_HOST}:${MESH_PORT}" "$CONFIG" 2>/dev/null; then
        echo "PASS: mesh address ${MESH_HOST}:${MESH_PORT}"
    else
        echo "FAIL: expected address ${MESH_HOST}:${MESH_PORT} in $CONFIG"
        fail=1
    fi
    if grep -q "$TLS_DOMAIN" "$CONFIG" 2>/dev/null; then
        echo "PASS: tls_domain $TLS_DOMAIN"
    else
        echo "WARN: tls_domain $TLS_DOMAIN not found in $CONFIG"
    fi
else
    echo "FAIL: missing $CONFIG"
    fail=1
fi

echo "==> hermes share in disk.toml (path + direction)"
if [[ -f "$CONFIG" ]]; then
    if grep -q 'hermes-artefacts' "$CONFIG"; then
        echo "PASS: hermes-artefacts share declared"
        grep -A6 'name = "hermes-artefacts"' "$CONFIG" 2>/dev/null | head -8 || true
        if grep -A6 'name = "hermes-artefacts"' "$CONFIG" | grep -q "receive_only"; then
            echo "PASS: hermes intended_direction receive_only"
        else
            echo "WARN: hermes share should be receive_only per mesh ACL (DISK-RB-003)"
        fi
        if grep -A6 'name = "hermes-artefacts"' "$CONFIG" | grep -q "$HERMES_PATH"; then
            echo "PASS: hermes path matches ${HERMES_PATH}"
        else
            echo "FAIL: hermes-artefacts path in disk.toml must be ${HERMES_PATH}"
            fail=1
        fi
    else
        echo "FAIL: hermes-artefacts missing from $CONFIG (see DISK-RB-003 §3 disk share init)"
        fail=1
    fi
fi

echo "==> bash MVP conflict check (DISK-RB-003)"
BASH_MVP="gui/$(id -u)/one.arcanada.disk-hermes-sync"
if launchctl print "$BASH_MVP" >/dev/null 2>&1; then
    echo "FAIL: bash rsync MVP still loaded — bootout before Rust daemon hermes sync"
    echo "  launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/one.arcanada.disk-hermes-sync.plist"
    fail=1
else
    echo "PASS: bash MVP not loaded"
fi
if pgrep -af 'disk-hermes-sync|rsync.*data/hermes' 2>/dev/null | grep -v pgrep; then
    echo "WARN: rsync/hermes bash process still running"
else
    echo "PASS: no rsync writer on hermes path"
fi

STATE_DIR="${DISK_STATE_DIR:-$HOME/.local/share/disk-arcana}"
NODE_ID=$(grep -E '^id = ' "$CONFIG" 2>/dev/null | head -1 | sed 's/.*"\(.*\)".*/\1/' || echo mac-operator)
API_KEY="${STATE_DIR}/api-key-${NODE_ID}"
echo "==> persisted api_key (${API_KEY})"
if [[ -f "$API_KEY" ]]; then
    echo "PASS: api_key file present"
else
    echo "WARN: missing api_key — hermes share may stay unauthenticated until datarim task writes it"
fi

echo "==> disk CLI build (session-refresh fix needs post-DISK-0067 binary)"
if command -v disk >/dev/null; then
    DISK_BIN=$(command -v disk)
    disk --version 2>/dev/null | head -1 || true
    if file "$DISK_BIN" 2>/dev/null | grep -q 'Mach-O.*arm64'; then
        echo "PASS: disk is Mach-O arm64"
    elif file "$DISK_BIN" 2>/dev/null | grep -qi 'ELF'; then
        echo "FAIL: disk is Linux ELF — exec format error on macOS; build natively: cargo install --path crates/disk-cli"
        fail=1
    else
        echo "WARN: could not verify disk binary format"
    fi
else
    echo "WARN: disk not in PATH"
fi

echo "==> hermes local path (${HERMES_PATH})"
if [[ -d "$HERMES_PATH" ]]; then
    echo "PASS: hermes path exists"
else
    echo "WARN: hermes path missing — creating skeleton (images/, documents/)"
    mkdir -p "${HERMES_PATH}/images" "${HERMES_PATH}/documents"
fi
for sub in images documents; do
    if [[ -d "${HERMES_PATH}/${sub}" ]]; then
        echo "PASS: ${HERMES_PATH}/${sub}"
    else
        mkdir -p "${HERMES_PATH}/${sub}"
        echo "CREATED: ${HERMES_PATH}/${sub}"
    fi
done

echo "==> mac-operator leaf cert"
if [[ -f "${TLS_DIR}/cert.pem" ]]; then
    subj=$(openssl x509 -in "${TLS_DIR}/cert.pem" -noout -subject 2>/dev/null || true)
    echo "$subj"
    if echo "$subj" | grep -q 'mac-operator'; then
        echo "PASS: leaf CN mac-operator"
    else
        echo "WARN: leaf CN may not be mac-operator"
    fi
else
    echo "FAIL: missing ${TLS_DIR}/cert.pem"
    fail=1
fi

echo "==> mTLS probe to mesh (${MESH_HOST}:${MESH_PORT})"
if timeout 8 openssl s_client -connect "${MESH_HOST}:${MESH_PORT}" \
    -servername "$TLS_DOMAIN" \
    -cert "${TLS_DIR}/cert.pem" -key "${TLS_DIR}/key.pem" \
    -CAfile "${TLS_DIR}/ca.pem" </dev/null 2>&1 | grep -q 'Verify return code: 0'; then
    echo "PASS: mTLS verify 0 from Mac"
else
    echo "FAIL: mTLS handshake from Mac"
    fail=1
fi

echo "==> LaunchAgent ($LABEL)"
if launchctl print "$LABEL" >/dev/null 2>&1; then
    echo "PASS: LaunchAgent loaded"
    launchctl print "$LABEL" 2>/dev/null | grep -E 'state =|pid =|last exit' | head -5 || true
else
    echo "FAIL: LaunchAgent not loaded in gui domain"
    fail=1
fi

print_share_summary() {
    local label="$1"
    echo "==> share state summary ($label)"
    if ! curl -sf --max-time 5 "$STATUS_URL" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for s in d.get('shares',[]):
    print(f\"  {s.get('name')}: state={s.get('state')} last_error={s.get('last_error')!r} last_success={s.get('last_success_at')}\")
bad=[s for s in d.get('shares',[]) if s.get('state')=='server_unreachable']
hermes=[s for s in d.get('shares',[]) if s.get('name')=='hermes-artefacts']
if bad:
    print('FAIL: server_unreachable on', [s.get('name') for s in bad])
    sys.exit(1)
if hermes and hermes[0].get('state') not in ('idle','syncing'):
    print('FAIL: hermes-artefacts not idle/syncing:', hermes[0].get('state'))
    sys.exit(1)
print('PASS: all shares idle/syncing')
"; then
        return 1
    fi
    return 0
}

echo "==> daemon /status (before kickstart)"
curl -sf --max-time 5 "$STATUS_URL" | python3 -m json.tool 2>/dev/null || fail=1
print_share_summary "before" || true

if [[ "$DO_KICKSTART" == "1" ]]; then
    echo "==> kickstart $LABEL"
    launchctl kickstart -k "$LABEL"
    sleep 5
    echo "==> POST $SYNC_URL"
    curl -sf -X POST "$SYNC_URL" || true
    echo "==> soak ${SOAK_SECONDS}s polling hermes-artefacts"
    end=$((SECONDS + SOAK_SECONDS))
    while (( SECONDS < end )); do
        if print_share_summary "soak"; then
            break
        fi
        sleep 10
        curl -sf -X POST "$SYNC_URL" >/dev/null 2>&1 || true
    done
    echo "==> final /status"
    curl -sf --max-time 5 "$STATUS_URL" | python3 -m json.tool || fail=1
fi

print_share_summary "final" || fail=1

exit "$fail"
