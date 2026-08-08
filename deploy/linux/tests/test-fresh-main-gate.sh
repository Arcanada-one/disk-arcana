#!/usr/bin/env bash
# INFRA-0370: behavioral contract for the pre-delivery origin/main freshness gate.

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
GATE="${FRESH_MAIN_GATE_OVERRIDE:-$ROOT/scripts/require-fresh-main.sh}"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

git init --bare "$TMP/remote.git" >/dev/null
git init "$TMP/source" >/dev/null
git -C "$TMP/source" config user.name INFRA-0370
git -C "$TMP/source" config user.email infra-0370@example.invalid
printf 'generation-a\n' >"$TMP/source/payload"
git -C "$TMP/source" add payload
git -C "$TMP/source" commit -m generation-a >/dev/null
git -C "$TMP/source" branch -M main
git -C "$TMP/source" remote add origin "$TMP/remote.git"
git -C "$TMP/source" push -u origin main >/dev/null
sha_a="$(git -C "$TMP/source" rev-parse HEAD)"

delivery_spy="$TMP/delivered"
bash "$GATE" "$sha_a" "$TMP/remote.git" && : >"$delivery_spy"
[[ -f "$delivery_spy" ]] || fail "fresh exact main blocked delivery"
printf 'PASS  fresh origin/main equal to built SHA permits delivery\n'

rm -f "$delivery_spy"
printf 'generation-b\n' >>"$TMP/source/payload"
git -C "$TMP/source" add payload
git -C "$TMP/source" commit -m generation-b >/dev/null
git -C "$TMP/source" push origin main >/dev/null
if bash "$GATE" "$sha_a" "$TMP/remote.git" && : >"$delivery_spy"; then
  fail "stale built SHA passed after origin/main advanced"
fi
[[ ! -e "$delivery_spy" ]] || fail "stale-main gate allowed the delivery side effect"
printf 'PASS  advanced origin/main blocks stale delivery before its side effect\n'
