#!/usr/bin/env bash
# DISK-0070: provisioning a secondary share must not unserve the shares
# already declared in DISK_SHARE_ROOTS.
#
# The regression this pins: `provision-hermes-share.sh` used to rewrite the
# whole variable (`sed s|^DISK_SHARE_ROOTS=.*|DISK_SHARE_ROOTS=<new>|`), so
# adding `hermes-artefacts` dropped every previously declared share. On
# arcana-agents that silently unserved `datarim-kb` — the server armed one
# watcher, the client kept reporting `state=syncing` / `last_error=null`, and
# `bytes_received_session` stayed at 0 with no error on either side.
#
# The test drives the real sed expression from the script rather than a copy,
# so a future rewrite of that line cannot pass while reintroducing the bug.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
PROVISIONER="${PROVISIONER_OVERRIDE:-$REPO_ROOT/deploy/linux/provision-hermes-share.sh}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[[ -f "$PROVISIONER" ]] || fail "provisioner not found at $PROVISIONER"

# The line under test, lifted verbatim from the provisioner so the test cannot
# drift into asserting a private copy of the logic.
sed_expr="$(grep -oE 's\|\^DISK_SHARE_ROOTS=[^"]*\|' "$PROVISIONER" | head -1)"
[[ -n "$sed_expr" ]] || fail "could not extract the DISK_SHARE_ROOTS sed expression"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

env_file="$work/disk-arcana.env"
cat >"$env_file" <<'EOF'
DISK_SYNC_ROOT=/home/dev/arcanada/datarim
DISK_SHARE_ROOTS=datarim-kb:/home/dev/arcanada/datarim
DISK_DB_PATH=/home/dev/.local/share/disk-arcana/disk.db
EOF

SHARE_ROOTS_LINE="hermes-artefacts:/var/lib/disk-arcana/shares/hermes-artefacts"
expr_expanded="${sed_expr//\$\{SHARE_ROOTS_LINE\}/$SHARE_ROOTS_LINE}"

# BSD and GNU sed differ on -i; write through a temp file to stay portable.
sed "$expr_expanded" "$env_file" >"$env_file.new"
mv "$env_file.new" "$env_file"

result="$(grep '^DISK_SHARE_ROOTS=' "$env_file" | cut -d= -f2-)"

# 1. The share that was already there must survive.
case "$result" in
  *datarim-kb:/home/dev/arcanada/datarim*) ;;
  *) fail "pre-existing share datarim-kb was dropped; DISK_SHARE_ROOTS=$result" ;;
esac

# 2. The new share must be present.
case "$result" in
  *hermes-artefacts:/var/lib/disk-arcana/shares/hermes-artefacts*) ;;
  *) fail "new share hermes-artefacts was not added; DISK_SHARE_ROOTS=$result" ;;
esac

# 3. Both must be readable as a comma-separated list, in that order, with no
#    stray separators — the server parses this with a plain split on ','.
expected="datarim-kb:/home/dev/arcanada/datarim,hermes-artefacts:/var/lib/disk-arcana/shares/hermes-artefacts"
[[ "$result" == "$expected" ]] || fail "unexpected value: '$result' != '$expected'"

# 4. Every entry must still parse as share:/absolute/path.
IFS=',' read -r -a entries <<<"$result"
[[ "${#entries[@]}" -eq 2 ]] || fail "expected 2 entries, got ${#entries[@]} in '$result'"
for entry in "${entries[@]}"; do
  [[ "$entry" == *:/* ]] || fail "entry '$entry' is not share:/absolute/path"
done

echo "DISK-0070 share-roots append: PASS (${#entries[@]} shares preserved)"
