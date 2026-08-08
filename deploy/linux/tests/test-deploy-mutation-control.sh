#!/usr/bin/env bash
# INFRA-0370: prove the deploy suite detects loss of a load-bearing rollback step.

set -euo pipefail
IFS=$'\n\t'

ROOT="$(git rev-parse --show-toplevel)"
SOURCE="$ROOT/deploy/linux/deploy-server.sh"
SUITE="$ROOT/deploy/linux/tests/test-deploy-server.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

MUTANT="$TMP/deploy-server-without-unit-restore.sh"
OUTPUT="$TMP/mutation-output"

# shellcheck disable=SC2016
sed 's@    ! restore_one "$backup/$UNIT_NAME" "$LIVE_UNIT" ||@    ! true ||@' \
  "$SOURCE" >"$MUTANT"
chmod 0755 "$MUTANT"

if cmp -s "$SOURCE" "$MUTANT"; then
  printf 'FAIL  rollback mutation did not change the helper\n' >&2
  exit 1
fi

if DEPLOYER_OVERRIDE="$MUTANT" bash "$SUITE" >"$OUTPUT" 2>&1; then
  printf 'FAIL  deploy suite accepted a helper with unit restoration disabled\n' >&2
  exit 1
fi

if ! grep -qF 'old unit hash was not restored' "$OUTPUT"; then
  sed -n '1,100p' "$OUTPUT" >&2
  printf 'FAIL  mutation failed for an unexpected reason\n' >&2
  exit 1
fi

printf 'PASS  deploy suite kills a mutant with the unit rollback step disabled\n'
