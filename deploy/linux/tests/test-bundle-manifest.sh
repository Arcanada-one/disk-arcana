#!/usr/bin/env bash
# INFRA-0370: local manifest-bound bundle preflight contract.
#
# This test deliberately stays below deployment: it creates a fake bundle,
# validates its exact inventory and commit identity, and proves every rejected
# preflight leaves the bundle tree byte-for-byte unchanged.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
VALIDATOR="${VALIDATOR_OVERRIDE:-$REPO_ROOT/deploy/linux/validate-deploy-bundle.sh}"

EXPECTED_COMMIT="0123456789abcdef0123456789abcdef01234567"
MEMBERS=(
  disk-arcana-server
  disk-arcana-server.service
  deploy-server.sh
  deploy-server-broker.sh
  provision-deploy-broker.sh
  disk-arcana-deploy.sudoers
  commit
)

failures=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/disk-arcana-bundle-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BASE="$WORK/base"
CASE="$WORK/case"

pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; failures=$((failures + 1)); }

run_validator() {
  bash "$VALIDATOR" "$@"
}

snapshot_tree() {
  local root="$1"
  (
    cd "$root"
    while IFS= read -r -d '' item; do
      if [[ -L "$item" ]]; then
        printf 'L %s -> %s\n' "$item" "$(readlink "$item")"
      elif [[ -f "$item" ]]; then
        printf 'F %s ' "$item"
        sha256sum "$item" | awk '{print $1}'
      elif [[ -d "$item" ]]; then
        printf 'D %s\n' "$item"
      else
        printf 'O %s\n' "$item"
      fi
    done < <(find . -mindepth 1 -print0 | LC_ALL=C sort -z)
  )
}

seed_bundle() {
  rm -rf "$BASE"
  mkdir -p "$BASE"
  for member in "${MEMBERS[@]}"; do
    if [[ "$member" == commit ]]; then
      printf '%s\n' "$EXPECTED_COMMIT" >"$BASE/$member"
    else
      printf 'fixture\n' >"$BASE/$member"
    fi
  done
  run_validator create --root "$BASE" --commit "$EXPECTED_COMMIT"
}

clone_case() {
  rm -rf "$CASE"
  cp -a "$BASE" "$CASE"
}

expect_rejected_without_mutation() {
  local label="$1"
  local log_name="${label//[^[:alnum:]]/_}.log"
  local before after status

  before="$(snapshot_tree "$CASE")"
  set +e
  run_validator verify --root "$CASE" --expected-commit "$EXPECTED_COMMIT" \
    >"$WORK/$log_name" 2>&1
  status=$?
  set -e

  if (( status != 0 )); then
    pass "$label rejects the bundle"
  else
    fail "$label unexpectedly accepts the bundle"
  fi

  after="$(snapshot_tree "$CASE")"
  if [[ "$before" == "$after" ]]; then
    pass "$label leaves the target tree unchanged"
  else
    fail "$label mutated the target tree"
  fi
}

expect_create_rejected_without_mutation() {
  local before after status

  before="$(snapshot_tree "$CASE")"
  set +e
  run_validator create --root "$CASE" --commit "$EXPECTED_COMMIT" \
    >"$WORK/create-extra.log" 2>&1
  status=$?
  set -e

  if (( status != 0 )); then
    pass "create rejects an extra member"
  else
    fail "create unexpectedly accepts an extra member"
  fi

  after="$(snapshot_tree "$CASE")"
  if [[ "$before" == "$after" ]]; then
    pass "create precheck leaves the target tree unchanged"
  else
    fail "create precheck mutated the target tree"
  fi
}

expect_reason() {
  local label="$1"
  local expected="$2"
  local log_name="${label//[^[:alnum:]]/_}.log"

  if grep -Fq "$expected" "$WORK/$log_name"; then
    pass "$label reports: $expected"
  else
    fail "$label did not report: $expected"
  fi
}

printf '# valid deterministic bundle\n'
seed_bundle
first_manifest="$(<"$BASE/manifest.sha256")"
rm -f "$BASE/manifest.sha256"
run_validator create --root "$BASE" --commit "$EXPECTED_COMMIT"
second_manifest="$(<"$BASE/manifest.sha256")"
if [[ "$first_manifest" == "$second_manifest" ]]; then
  pass "member inventory and manifest are deterministic"
else
  fail "member inventory or manifest is not deterministic"
fi

expected_names="$(printf '%s\n' "${MEMBERS[@]}" | LC_ALL=C sort)"
actual_names="$(awk '{ print $2 }' "$BASE/manifest.sha256")"
if [[ "$actual_names" == "$expected_names" ]]; then
  pass "manifest inventory is canonically sorted and exact"
else
  fail "manifest inventory is not canonically sorted or exact"
fi

if run_validator verify --root "$BASE" --expected-commit "$EXPECTED_COMMIT"; then
  pass "valid bundle passes manifest and commit preflight"
else
  fail "valid bundle does not pass manifest and commit preflight"
fi

printf '\n# rejection and zero-mutation cases\n'

clone_case
rm -f "$CASE/disk-arcana-server"
expect_rejected_without_mutation "missing member"

clone_case
printf 'unexpected\n' >"$CASE/unexpected"
expect_rejected_without_mutation "extra member"

clone_case
rm -f "$CASE/disk-arcana-server"
ln -s disk-arcana-server.service "$CASE/disk-arcana-server"
expect_rejected_without_mutation "symlinked member"

clone_case
rm -f "$CASE/disk-arcana-server"
mkdir "$CASE/disk-arcana-server"
expect_rejected_without_mutation "non-regular member"

clone_case
printf 'tampered\n' >"$CASE/deploy-server.sh"
expect_rejected_without_mutation "tampered member"

clone_case
awk 'NR == 1 { sub(/^[0-9a-f]+/, "0000000000000000000000000000000000000000000000000000000000000000") } { print }' \
  "$CASE/manifest.sha256" >"$CASE/manifest.tmp"
mv "$CASE/manifest.tmp" "$CASE/manifest.sha256"
expect_rejected_without_mutation "manifest hash mismatch"

clone_case
awk 'NR == 1 { first = $0; next } NR == 2 { print $0; print first; next } { print }' \
  "$CASE/manifest.sha256" >"$CASE/manifest.tmp"
mv "$CASE/manifest.tmp" "$CASE/manifest.sha256"
expect_rejected_without_mutation "manifest inventory order mismatch"

clone_case
awk 'NR == 1 { sub(/  commit$/, "  unexpected") } { print }' \
  "$CASE/manifest.sha256" >"$CASE/manifest.tmp"
mv "$CASE/manifest.tmp" "$CASE/manifest.sha256"
expect_rejected_without_mutation "manifest unknown member"
expect_reason "manifest unknown member" "manifest names an unknown member"

clone_case
awk 'NR == 7 { sub(/  provision-deploy-broker\.sh$/, "  commit") } { print }' \
  "$CASE/manifest.sha256" >"$CASE/manifest.tmp"
mv "$CASE/manifest.tmp" "$CASE/manifest.sha256"
expect_rejected_without_mutation "manifest duplicate member"
expect_reason "manifest duplicate member" "manifest contains duplicate member"

clone_case
sed '$d' "$CASE/manifest.sha256" >"$CASE/manifest.tmp"
mv "$CASE/manifest.tmp" "$CASE/manifest.sha256"
expect_rejected_without_mutation "manifest missing member"
expect_reason "manifest missing member" "manifest member count mismatch"

clone_case
new_commit="fedcba9876543210fedcba9876543210fedcba98"
printf '%s\n' "$new_commit" >"$CASE/commit"
rm -f "$CASE/manifest.sha256"
run_validator create --root "$CASE" --commit "$new_commit"
expect_rejected_without_mutation "expected commit mismatch"

clone_case
printf 'not-a-commit\n' >"$CASE/commit"
expect_rejected_without_mutation "malformed commit identity"
expect_reason "malformed commit identity" "commit member is not a 40-character lowercase hexadecimal SHA"

clone_case
printf 'unexpected\n' >"$CASE/unexpected"
rm -f "$CASE/manifest.sha256"
expect_create_rejected_without_mutation

printf '\n'
if [[ "$failures" -ne 0 ]]; then
  printf '%s bundle-manifest check(s) failed\n' "$failures" >&2
  exit 1
fi

printf 'All bundle-manifest checks passed\n'
