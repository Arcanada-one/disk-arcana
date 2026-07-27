#!/usr/bin/env bash
# apply-mesh-acl.sh — render, install, and GPG-sign mesh ACL on arcana-agents.
#
# Run on the host that holds the ACL signing private key OR edit+sign locally
# and scp the pair to arcana-agents (see DISK-RB-007).
#
# Usage:
#   DEV_FP=<blake3hex> MAC_FP=<blake3hex> sudo ./apply-mesh-acl.sh
#
# Optional:
#   ACL_TEMPLATE=deploy/prod/disk-acl.mesh.yaml.example
#   DISK_ACL_PATH=/etc/disk-arcana/disk-acl.yaml
#   GPG_KEY=disk-acl-signer@arcanada.ai

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ACL_TEMPLATE="${ACL_TEMPLATE:-$REPO_ROOT/deploy/prod/disk-acl.mesh.yaml.example}"
DISK_ACL_PATH="${DISK_ACL_PATH:-/etc/disk-arcana/disk-acl.yaml}"
DISK_ACL_SIG_PATH="${DISK_ACL_SIG_PATH:-${DISK_ACL_PATH}.asc}"
GPG_KEY="${GPG_KEY:-disk-acl-signer@arcanada.ai}"

: "${DEV_FP:?set DEV_FP (blake3 hex of agents leaf cert)}"
: "${MAC_FP:?set MAC_FP (blake3 hex of Mac leaf cert)}"

rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT

sed \
  -e "s/\${DEV_FP}/$DEV_FP/g" \
  -e "s/\${MAC_FP}/$MAC_FP/g" \
  "$ACL_TEMPLATE" > "$rendered"

if [[ -f "$DISK_ACL_PATH" ]]; then
  cp -a "$DISK_ACL_PATH" "${DISK_ACL_PATH}.prev"
fi

install -m 640 -o root -g disk-arcana "$rendered" "$DISK_ACL_PATH"

gpg --batch --detach-sign --armor \
  --default-key "$GPG_KEY" \
  -o "$DISK_ACL_SIG_PATH" \
  "$DISK_ACL_PATH"

chown root:disk-arcana "$DISK_ACL_SIG_PATH"
chmod 640 "$DISK_ACL_SIG_PATH"

if systemctl is-active disk-arcana-server &>/dev/null; then
  systemctl kill --signal=SIGHUP disk-arcana-server
fi

echo "ACL installed: $DISK_ACL_PATH (+ signature). Previous backup: ${DISK_ACL_PATH}.prev"
