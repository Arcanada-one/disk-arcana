#!/usr/bin/env bash
# INFRA-0370: static contract for one-build, staging-first, broker-only deploys.
# shellcheck disable=SC2016

set -euo pipefail
# Literals below intentionally match unexpanded workflow expressions.

ROOT="$(git rev-parse --show-toplevel)"
WORKFLOW="${WORKFLOW_OVERRIDE:-$ROOT/.github/workflows/release-deploy.yml}"
SHARE_WORKFLOW="${SHARE_WORKFLOW_OVERRIDE:-$ROOT/.github/workflows/deploy-arcana-agents-share.yml}"
PROBE_WORKFLOW="${PROBE_WORKFLOW_OVERRIDE:-$ROOT/.github/workflows/deploy-probe.yml}"
INSTALLER="$ROOT/deploy/linux/install.sh"

fail() {
  printf 'FAIL  %s\n' "$1" >&2
  exit 1
}

assert_command_before() {
  local block="$1" gate="$2" delivery="$3" label="$4" gate_line delivery_line
  gate_line="$(awk -v expected="$gate" '
    {line=$0; sub(/^[[:space:]]+/, "", line); sub(/[[:space:]]+$/, "", line)}
    line == expected {print NR; exit}
  ' <<<"$block")"
  delivery_line="$(awk -v prefix="$delivery" '
    {line=$0; sub(/^[[:space:]]+/, "", line); sub(/[[:space:]]+$/, "", line)}
    index(line, prefix) == 1 {print NR; exit}
  ' <<<"$block")"
  [[ -n "$gate_line" ]] || fail "$label is missing the freshness gate"
  [[ -n "$delivery_line" ]] || fail "$label is missing its delivery command"
  (( gate_line < delivery_line )) || fail "$label runs before its freshness gate"
}

count_exact_command() {
  local file="$1" expected="$2"
  awk -v expected="$expected" '
    {line=$0; sub(/^[[:space:]]+/, "", line); sub(/[[:space:]]+$/, "", line)}
    line == expected {count++}
    END {print count + 0}
  ' "$file"
}

grep -qF 'name: Assemble manifest-bound deployment bundle' "$WORKFLOW" ||
  fail "release build does not assemble the fixed deployment bundle"
grep -qF 'bash deploy/linux/validate-deploy-bundle.sh create' "$WORKFLOW" ||
  fail "release build does not create the manifest from the checked-out commit"
grep -qF 'bash deploy/linux/validate-deploy-bundle.sh verify' "$WORKFLOW" ||
  fail "release build does not verify the assembled manifest"
grep -qF "path: \${{ runner.temp }}/disk-deploy-bundle" "$WORKFLOW" ||
  fail "artifact upload is not the complete fixed bundle"
grep -qF '          - stage' "$WORKFLOW" || fail "stage-only dispatch target is absent"
grep -qF "artifact_digest: \${{ steps.artifact.outputs.artifact-digest }}" "$WORKFLOW" ||
  fail "build does not export the immutable artifact digest"
[[ "$(sed -n '/^permissions:/,/^env:/p' "$WORKFLOW")" == *'contents: read'* ]] ||
  fail "top-level release workflow permission is broader than read-only"
grep -qF 'install.sh is bootstrap-only' "$INSTALLER" ||
  fail "legacy installer is not guarded as first-install-only"

dev_block="$(sed -n '/^  deploy-stage:/,/^  deploy-prod:/p' "$WORKFLOW")"
prod_block="$(sed -n '/^  deploy-prod:/,$p' "$WORKFLOW")"
share_block="$(sed -n '/^  deliver:/,$p' "$SHARE_WORKFLOW")"
linux_release_block="$(sed -n '/^  attach-linux-release:/,/^  build-windows-client:/p' "$WORKFLOW")"
windows_release_block="$(sed -n '/^  build-windows-client:/,/^  build-linux-client:/p' "$WORKFLOW")"
linux_client_release_block="$(sed -n '/^  build-linux-client:/,/^  build-macos-client:/p' "$WORKFLOW")"
macos_release_block="$(sed -n '/^  build-macos-client:/,/^  deploy-stage:/p' "$WORKFLOW")"
share_diff_block="$(sed -n '/name: Diff share drop-in/,/name: Install share drop-in/p' "$SHARE_WORKFLOW")"
share_install_block="$(sed -n '/name: Install share drop-in/,$p' "$SHARE_WORKFLOW")"
[[ "$dev_block" == *"github.event.inputs.target == 'prod'"* ]] ||
  fail "production dispatch does not first run staging in the same workflow"
[[ "$dev_block" == *"github.ref == 'refs/heads/main'"* ]] ||
  fail "staging deploy does not independently require exact main"
[[ "$dev_block" == *'environment: staging'* ]] ||
  fail "staging deploy does not use the protected staging environment"
[[ "$dev_block" == *'group: disk-arcana-stage'* ]] ||
  fail "staging deploy does not require the repository-restricted runner group"
[[ "$dev_block" == *'labels: [self-hosted, Linux, X64, disk-arcana-stage]'* ]] ||
  fail "staging deploy does not require the dedicated runner label"
[[ "$prod_block" == *'needs: [build, deploy-stage]'* ]] ||
  fail "production deploy is not causally gated on the same-run staging job"
[[ "$prod_block" == *"github.ref == 'refs/heads/main'"* ]] ||
  fail "production deploy does not independently require exact main"
[[ "$prod_block" == *'runs-on: [self-hosted, Linux, X64, disk-arcana-prod]'* ]] ||
  fail "production deploy does not require the dedicated runner label"

[[ "$share_block" == *"github.ref == 'refs/heads/main'"* ]] ||
  fail "arcana-agents share delivery is not gated to main"
[[ "$share_block" == *'environment: production'* ]] ||
  fail "arcana-agents share delivery does not use a protected environment"
[[ "$share_block" == *'bash scripts/require-fresh-main.sh "$GITHUB_SHA"'* ]] ||
  fail "arcana-agents share delivery does not freshly read origin/main"

[[ "$(grep -cF 'name: Fresh exact-main release gate' "$WORKFLOW")" -eq 4 ]] ||
  fail "every release-delivery path must freshly gate its built SHA against origin/main"
[[ "$(count_exact_command "$WORKFLOW" 'run: bash scripts/require-fresh-main.sh "$BUILT_SHA"')" -eq 4 ]] ||
  fail "release delivery does not require fresh main to equal its built SHA"
[[ "$(count_exact_command "$WORKFLOW" 'bash scripts/require-fresh-main.sh "$EXPECTED_BUILD_COMMIT"')" -eq 2 ]] ||
  fail "broker delivery does not freshly require origin/main to equal the built SHA"
[[ "$(count_exact_command "$SHARE_WORKFLOW" 'bash scripts/require-fresh-main.sh "$GITHUB_SHA"')" -eq 2 ]] ||
  fail "share delivery does not execute both fresh-main gates"

for release_block in \
  "$linux_release_block" "$windows_release_block" \
  "$linux_client_release_block" "$macos_release_block"; do
  assert_command_before "$release_block" \
    'run: bash scripts/require-fresh-main.sh "$BUILT_SHA"' \
    'uses: softprops/action-gh-release@' \
    "release attachment"
done
assert_command_before "$dev_block" \
  'bash scripts/require-fresh-main.sh "$EXPECTED_BUILD_COMMIT"' \
  'sudo -n /usr/local/sbin/disk-arcana-deploy-broker --deploy' \
  "staging broker delivery"
assert_command_before "$prod_block" \
  'bash scripts/require-fresh-main.sh "$EXPECTED_BUILD_COMMIT"' \
  'sudo -n /usr/local/sbin/disk-arcana-deploy-broker --deploy' \
  "production broker delivery"
assert_command_before "$share_diff_block" \
  'bash scripts/require-fresh-main.sh "$GITHUB_SHA"' \
  'bash deploy/linux/install-user-share-dropin.sh' \
  "share diff"
assert_command_before "$share_install_block" \
  'bash scripts/require-fresh-main.sh "$GITHUB_SHA"' \
  'bash deploy/linux/install-user-share-dropin.sh --install' \
  "share installation"

grep -qF 'default: arcana-prod' "$PROBE_WORKFLOW" || fail "INFRA-0389 default runner routing changed"
! grep -qE '^[[:space:]]*-[[:space:]]*arcana-prod-ci[[:space:]]*$' "$PROBE_WORKFLOW" ||
  fail "INFRA-0389 private-only runner leaked into the public probe"
grep -qF '[[ "${{ steps.state.outputs.unit_file_state }}" == "enabled" ]]' "$PROBE_WORKFLOW" ||
  fail "deploy probe does not require exact UnitFileState=enabled"

for block in "$dev_block" "$prod_block"; do
  [[ "$block" == *'/usr/local/sbin/disk-arcana-deploy-broker --deploy'* ]] ||
    fail "deploy job bypasses the installed broker"
  # shellcheck disable=SC2016
  [[ "$block" == *'authorization_id="${GITHUB_RUN_ID}'* ]] ||
    fail "deploy job is not bound to a root-issued run authorization"
  [[ "$block" == *"artifact-ids: \${{ needs.build.outputs.artifact_id }}"* ]] ||
    fail "deploy job does not download the immutable same-run artifact ID"
  [[ "$block" == *"EXPECTED_ARTIFACT_DIGEST: \${{ needs.build.outputs.artifact_digest }}"* ]] ||
    fail "deploy job does not attest the same-run artifact digest"
  [[ "$block" != *'cp /tmp/disk-release/'* ]] || fail "deploy job retains direct binary activation"
  [[ "$block" != *'run: systemctl restart disk-arcana-server'* ]] ||
    fail "deploy job retains direct service restart"
  [[ "$block" == *"printf 'health=ok\\n'"* ]] ||
    fail "deploy job does not emit a bounded health result"
  [[ "$block" == *'[[ "$(systemctl show disk-arcana-server -p UnitFileState --value)" == enabled ]]'* ]] ||
    fail "deploy job does not require exact UnitFileState=enabled"
  [[ "$block" != *$'http://127.0.0.1:9446/health\n'* ]] ||
    fail "deploy job prints the raw health response"
done

if rg -q --glob '!test-release-deploy-contract.sh' --glob '!test-deploy-broker.sh' \
    --glob '!provision-deploy-broker.sh' \
    'disk-arcana-install-unit|install-systemd-unit\.sh' \
    "$ROOT/.github" "$ROOT/deploy/linux" "$ROOT/scripts"; then
  fail "retired unit-only release path is still reachable"
fi

if [[ "${DISK_ARCANA_ORDER_FIXTURE_CHILD:-}" != 1 ]]; then
  fixture_root="$(mktemp -d)"
  trap 'rm -rf -- "$fixture_root"' EXIT
  reordered_workflow="$fixture_root/release-reordered.yml"
  fixture_output="$fixture_root/output"
  sed \
    '/bash scripts\/require-fresh-main.sh "$EXPECTED_BUILD_COMMIT"/{h;d}; /"$BUNDLE" "$authorization_id"/G' \
    "$WORKFLOW" >"$reordered_workflow"
  set +e
  DISK_ARCANA_ORDER_FIXTURE_CHILD=1 \
    WORKFLOW_OVERRIDE="$reordered_workflow" \
    SHARE_WORKFLOW_OVERRIDE="$SHARE_WORKFLOW" \
    PROBE_WORKFLOW_OVERRIDE="$PROBE_WORKFLOW" \
    "$0" >"$fixture_output" 2>&1
  fixture_rc=$?
  set -e
  [[ "$fixture_rc" -ne 0 ]] || fail "reordered-after-delivery fixture passed"
  grep -qF 'FAIL  staging broker delivery runs before its freshness gate' "$fixture_output" ||
    fail "reordered-after-delivery fixture failed for an unintended reason"
  printf 'PASS  reordered broker-delivery fixture is rejected for freshness ordering\n'

  reordered_share="$fixture_root/share-reordered.yml"
  sed '/name: Install share drop-in/,$ {
    /bash scripts\/require-fresh-main.sh "$GITHUB_SHA"/{h;d}
    /bash deploy\/linux\/install-user-share-dropin.sh --install/G
  }' "$SHARE_WORKFLOW" >"$reordered_share"
  set +e
  DISK_ARCANA_ORDER_FIXTURE_CHILD=1 \
    WORKFLOW_OVERRIDE="$WORKFLOW" \
    SHARE_WORKFLOW_OVERRIDE="$reordered_share" \
    PROBE_WORKFLOW_OVERRIDE="$PROBE_WORKFLOW" \
    "$0" >"$fixture_output" 2>&1
  fixture_rc=$?
  set -e
  [[ "$fixture_rc" -ne 0 ]] || fail "reordered share-delivery fixture passed"
  grep -qF 'FAIL  share installation runs before its freshness gate' "$fixture_output" ||
    fail "reordered share-delivery fixture failed for an unintended reason"
  printf 'PASS  reordered share-delivery fixture is rejected for freshness ordering\n'

  inert_workflow="$fixture_root/release-inert-gates.yml"
  sed \
    -e 's#run: bash scripts/require-fresh-main#run: echo bash scripts/require-fresh-main#' \
    -e 's#^\([[:space:]]*\)bash scripts/require-fresh-main#\1echo bash scripts/require-fresh-main#' \
    "$WORKFLOW" >"$inert_workflow"
  set +e
  DISK_ARCANA_ORDER_FIXTURE_CHILD=1 \
    WORKFLOW_OVERRIDE="$inert_workflow" \
    SHARE_WORKFLOW_OVERRIDE="$SHARE_WORKFLOW" \
    PROBE_WORKFLOW_OVERRIDE="$PROBE_WORKFLOW" \
    "$0" >"$fixture_output" 2>&1
  fixture_rc=$?
  set -e
  [[ "$fixture_rc" -ne 0 ]] || fail "inert release freshness fixture passed"
  grep -qF 'FAIL  release delivery does not require fresh main to equal its built SHA' \
    "$fixture_output" || fail "inert release freshness fixture failed for an unintended reason"
  printf 'PASS  inert release freshness commands are rejected as non-executable gates\n'

  inert_share="$fixture_root/share-inert-gates.yml"
  sed 's#^\([[:space:]]*\)bash scripts/require-fresh-main#\1echo bash scripts/require-fresh-main#' \
    "$SHARE_WORKFLOW" >"$inert_share"
  set +e
  DISK_ARCANA_ORDER_FIXTURE_CHILD=1 \
    WORKFLOW_OVERRIDE="$WORKFLOW" \
    SHARE_WORKFLOW_OVERRIDE="$inert_share" \
    PROBE_WORKFLOW_OVERRIDE="$PROBE_WORKFLOW" \
    "$0" >"$fixture_output" 2>&1
  fixture_rc=$?
  set -e
  [[ "$fixture_rc" -ne 0 ]] || fail "inert share freshness fixture passed"
  grep -qF 'FAIL  share delivery does not execute both fresh-main gates' "$fixture_output" ||
    fail "inert share freshness fixture failed for an unintended reason"
  printf 'PASS  inert share freshness commands are rejected as non-executable gates\n'
fi

printf 'PASS  release workflow deploys one manifest-bound artifact through staging then production\n'
