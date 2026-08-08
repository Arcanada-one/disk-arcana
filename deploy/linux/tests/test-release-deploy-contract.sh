#!/usr/bin/env bash
# INFRA-0370: static contract for one-build, staging-first, broker-only deploys.

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
WORKFLOW="$ROOT/.github/workflows/release-deploy.yml"
INSTALLER="$ROOT/deploy/linux/install.sh"

fail() {
  printf 'FAIL  %s\n' "$1" >&2
  exit 1
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
[[ "$dev_block" == *"github.event.inputs.target == 'prod'"* ]] ||
  fail "production dispatch does not first run staging in the same workflow"
[[ "$prod_block" == *'needs: [build, deploy-stage]'* ]] ||
  fail "production deploy is not causally gated on the same-run staging job"

for block in "$dev_block" "$prod_block"; do
  [[ "$block" == *'/usr/local/sbin/disk-arcana-deploy-broker --deploy'* ]] ||
    fail "deploy job bypasses the installed broker"
  [[ "$block" == *"artifact-ids: \${{ needs.build.outputs.artifact_id }}"* ]] ||
    fail "deploy job does not download the immutable same-run artifact ID"
  [[ "$block" == *"EXPECTED_ARTIFACT_DIGEST: \${{ needs.build.outputs.artifact_digest }}"* ]] ||
    fail "deploy job does not attest the same-run artifact digest"
  [[ "$block" != *'cp /tmp/disk-release/'* ]] || fail "deploy job retains direct binary activation"
  [[ "$block" != *'run: systemctl restart disk-arcana-server'* ]] ||
    fail "deploy job retains direct service restart"
done

printf 'PASS  release workflow deploys one manifest-bound artifact through staging then production\n'
