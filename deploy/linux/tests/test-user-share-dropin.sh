#!/usr/bin/env bash
# DISK-0070: the user-scope drop-in installer must refuse any configuration
# that leaves DISK_SYNC_ROOT without a share_index watcher.
#
# This is the pre-flight twin of the server's startup warning: the outage on
# arcana-agents happened because a drop-in declared `hermes-artefacts` alone,
# so `datarim-kb` was served out of DISK_SYNC_ROOT but never watched — nothing
# indexed, clients pulling nothing, both ends reporting success. Catching that
# before the host is touched is cheaper than noticing it in a log afterwards.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
INSTALLER="${INSTALLER_OVERRIDE:-$REPO_ROOT/deploy/linux/install-user-share-dropin.sh}"
SHIPPED_DROPIN="$REPO_ROOT/deploy/linux/user-dropins/arcana-agents-shares.conf"

SYNC_ROOT="/home/dev/arcanada/datarim"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[[ -f "$INSTALLER" ]] || fail "installer not found at $INSTALLER"
[[ -f "$SHIPPED_DROPIN" ]] || fail "shipped drop-in not found at $SHIPPED_DROPIN"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

run_installer() {
  DISK_SYNC_ROOT_OVERRIDE="$SYNC_ROOT" \
    DISK_DROPIN_DIR="$work/dropins" \
    bash "$INSTALLER" --dropin "$1" >"$work/out.log" 2>&1
}

# 1. The shipped drop-in must satisfy its own contract — otherwise the file we
#    ask operators to install is the broken configuration.
if ! run_installer "$SHIPPED_DROPIN"; then
  cat "$work/out.log" >&2
  fail "the shipped arcana-agents drop-in does not pass the contract"
fi
grep -q 'contract OK' "$work/out.log" ||
  fail "expected 'contract OK' for the shipped drop-in, got: $(cat "$work/out.log")"

# 2. The exact outage configuration must be rejected.
cat >"$work/secondary-only.conf" <<'EOF'
[Service]
Environment=DISK_SHARE_ROOTS=hermes-artefacts:/var/lib/disk-arcana/shares/hermes-artefacts
EOF
if run_installer "$work/secondary-only.conf"; then
  fail "installer accepted the configuration that unserved datarim-kb"
fi
grep -q 'is not among the declared share roots' "$work/out.log" ||
  fail "rejection did not name the uncovered sync root: $(cat "$work/out.log")"

# 3. A malformed entry must be rejected rather than silently split.
cat >"$work/malformed.conf" <<'EOF'
[Service]
Environment=DISK_SHARE_ROOTS=datarim-kb
EOF
if run_installer "$work/malformed.conf"; then
  fail "installer accepted an entry without a path"
fi
grep -q 'malformed entry' "$work/out.log" ||
  fail "expected a malformed-entry error, got: $(cat "$work/out.log")"

# 4. A drop-in with no DISK_SHARE_ROOTS at all must be rejected, not treated as
#    "nothing to check".
cat >"$work/empty.conf" <<'EOF'
[Service]
Environment=DISK_REGISTER_NODE_MODE=enrolled
EOF
if run_installer "$work/empty.conf"; then
  fail "installer accepted a drop-in declaring no shares"
fi
grep -q 'declares no DISK_SHARE_ROOTS' "$work/out.log" ||
  fail "expected a no-shares error, got: $(cat "$work/out.log")"

# 5. Coverage is by path, not by share name — clients choose their own names.
cat >"$work/renamed.conf" <<EOF
[Service]
Environment=DISK_SHARE_ROOTS=some-other-name:$SYNC_ROOT
EOF
run_installer "$work/renamed.conf" ||
  fail "a differently named share covering sync_root should pass: $(cat "$work/out.log")"

# 6. A dry-run against a DIFFERING installed copy must succeed: a difference is
#    the expected result of a diff, not a failure. The first CI dispatch failed
#    exactly here — `diff`'s non-zero status killed the step under `set -e`.
installed_dir="$work/installed"
mkdir -p "$installed_dir"
cat >"$installed_dir/$(basename "$SHIPPED_DROPIN")" <<'EOF'
[Service]
Environment=DISK_SHARE_ROOTS=stale-share:/some/old/path
EOF
if ! DISK_SYNC_ROOT_OVERRIDE="$SYNC_ROOT" \
  DISK_DROPIN_DIR="$installed_dir" \
  bash "$INSTALLER" --dropin "$SHIPPED_DROPIN" >"$work/out.log" 2>&1; then
  cat "$work/out.log" >&2
  fail "dry-run must not fail merely because the installed copy differs"
fi
grep -q 'differs from the installed copy' "$work/out.log" ||
  fail "expected the differing-copy notice, got: $(cat "$work/out.log")"

# 7. Resolution must work from a session that does not own the unit — the CI
#    runner on arcana-agents executes as a different user, and `systemctl --user`
#    there reaches the caller's own bus, never the owner's.
if ! DISK_UNIT_OWNER="$(id -un)" \
  DISK_SYNC_ROOT_OVERRIDE="$SYNC_ROOT" \
  DISK_DROPIN_DIR="$work/dropins" \
  bash "$INSTALLER" --dropin "$SHIPPED_DROPIN" >"$work/out.log" 2>&1; then
  cat "$work/out.log" >&2
  fail "dry-run must work without the unit owner's systemd bus"
fi

# 8. install/verify must refuse a foreign session instead of half-applying.
for mode in --install --verify; do
  if DISK_UNIT_OWNER="definitely-not-$(id -un)" \
    DISK_SYNC_ROOT_OVERRIDE="$SYNC_ROOT" \
    DISK_DROPIN_DIR="$work/dropins" \
    bash "$INSTALLER" --dropin "$SHIPPED_DROPIN" "$mode" >"$work/out.log" 2>&1; then
    fail "$mode ran as the wrong user instead of refusing"
  fi
done

echo "DISK-0070 user drop-in contract: PASS (shipped drop-in valid, 3 bad configs rejected, diff/ownership guards held)"
