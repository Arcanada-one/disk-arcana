#!/usr/bin/env bash
# INFRA-0370: static contract for one-build, staging-first, broker-only deploys.
# shellcheck disable=SC2016

set -euo pipefail
# Literals below intentionally match unexpanded workflow expressions.

ROOT="$(git rev-parse --show-toplevel)"
WORKFLOW="${WORKFLOW_OVERRIDE:-$ROOT/.github/workflows/release-deploy.yml}"
SHARE_WORKFLOW="${SHARE_WORKFLOW_OVERRIDE:-$ROOT/.github/workflows/deploy-arcana-agents-share.yml}"
PROBE_WORKFLOW="${PROBE_WORKFLOW_OVERRIDE:-$ROOT/.github/workflows/deploy-probe.yml}"
STAGE_PROBE_WORKFLOW="${STAGE_PROBE_WORKFLOW_OVERRIDE:-$ROOT/.github/workflows/stage-runner-probe.yml}"
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

assert_unconditional_release_step() {
  local block="$1" label="$2" gate_step
  gate_step="$(awk '
    {
      raw=$0
      line=$0
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
      match(raw, /[^ ]/)
      indent=RSTART - 1
    }
    !in_gate && line == "- name: Fresh exact-main release gate" {
      in_gate=1
      step_indent=indent
    }
    in_gate && line != "- name: Fresh exact-main release gate" &&
      indent == step_indent && line ~ /^- / {exit}
    in_gate {print raw}
  ' <<<"$block")"
  [[ "$gate_step" == *'run: bash scripts/require-fresh-main.sh "$BUILT_SHA"'* ]] ||
    fail "$label is missing its executable freshness step"
  if grep -qE '^[[:space:]]*(if|continue-on-error)[[:space:]]*:' <<<"$gate_step"; then
    fail "$label freshness step is conditional or non-blocking"
  fi
}

assert_unconditional_shell_gate_before_delivery() {
  local block="$1" gate="$2" delivery="$3" label="$4"
  local run_line run_indent gate_line gate_indent first_indent first_line second_indent second_line
  local -a post_gate=()
  read -r run_line run_indent gate_line gate_indent < <(awk -v expected="$gate" '
    {
      raw=$0
      line=$0
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
      match(raw, /[^ ]/)
      indent=RSTART - 1
    }
    line == "run: |" {run_line=NR; run_indent=indent}
    line == expected {print run_line, run_indent, NR, indent; exit}
  ' <<<"$block")
  mapfile -t post_gate < <(awk -v expected="$gate" '
    {
      raw=$0
      line=$0
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
    }
    found && line != "" && line !~ /^#/ {
      match(raw, /[^ ]/)
      print RSTART - 1 "\t" line
      count++
      if (count == 2) exit
    }
    line == expected {found=1}
  ' <<<"$block")
  [[ -n "$run_line" && -n "$run_indent" && -n "$gate_line" && -n "$gate_indent" ]] ||
    fail "$label is missing its executable freshness gate"
  [[ "${#post_gate[@]}" -eq 2 ]] ||
    fail "$label freshness gate is not directly load-bearing on delivery"
  first_indent="${post_gate[0]%%$'\t'*}"
  first_line="${post_gate[0]#*$'\t'}"
  second_indent="${post_gate[1]%%$'\t'*}"
  second_line="${post_gate[1]#*$'\t'}"
  (( gate_indent == run_indent + 2 && first_indent == gate_indent && second_indent == gate_indent )) ||
    fail "$label freshness gate is not unconditional or load-bearing"
  [[ "$first_line" == authorization_id=* && "$second_line" == "$delivery"* ]] ||
    fail "$label freshness gate is not directly load-bearing on delivery"
}

assert_unconditional_shell_gate() {
  local block="$1" gate="$2" label="$3"
  local run_line run_indent gate_line gate_indent pre_gate_command
  read -r run_line run_indent < <(awk '
    {line=$0; sub(/^[[:space:]]+/, "", line); sub(/[[:space:]]+$/, "", line)}
    line == "run: |" {match($0, /[^ ]/); print NR, RSTART - 1; exit}
  ' <<<"$block")
  read -r gate_line gate_indent < <(awk -v expected="$gate" '
    {line=$0; sub(/^[[:space:]]+/, "", line); sub(/[[:space:]]+$/, "", line)}
    line == expected {match($0, /[^ ]/); print NR, RSTART - 1; exit}
  ' <<<"$block")
  pre_gate_command="$(awk -v expected="$gate" '
    {line=$0; sub(/^[[:space:]]+/, "", line); sub(/[[:space:]]+$/, "", line)}
    line == "run: |" {in_script=1; next}
    !in_script {next}
    line == expected {exit}
    line == "" || line == "set -euo pipefail" || line ~ /^#/ {next}
    {print line; exit}
  ' <<<"$block")"
  [[ -n "$run_line" && -n "$run_indent" && -n "$gate_line" && -n "$gate_indent" ]] ||
    fail "$label is missing its executable freshness gate"
  (( gate_indent == run_indent + 2 )) ||
    fail "$label freshness gate is not unconditional"
  [[ -z "$pre_gate_command" ]] ||
    fail "$label freshness gate is not unconditional"
}

assert_direct_stage_command() {
  local block="$1" expected="$2" label="$3"
  grep -qFx "          $expected" <<<"$block" ||
    fail "group-scoped stage probe does not execute $label directly"
}

extract_stage_readiness_script() {
  local block="$1"
  awk '
    found && ($0 == "" || /^          /) {
      sub(/^          /, "")
      print
      next
    }
    found {exit}
    /^        run: \|$/ {found=1}
  ' <<<"$block"
}

assert_reviewed_stage_readiness_script() {
  local block="$1" script_digest
  script_digest="$(extract_stage_readiness_script "$block" | sha256sum | awk '{print $1}')"
  [[ "$script_digest" == c1ae34d01a980b498311acb6513aac92ca1be4f5bdaa38b3f08eb0ceb3d66c6f ]] ||
    fail "group-scoped stage probe readiness script differs from the reviewed executable contract"
}

assert_reviewed_stage_source_script() {
  local block="$1" script_digest
  script_digest="$(extract_stage_readiness_script "$block" | sha256sum | awk '{print $1}')"
  [[ "$script_digest" == 2cf7df97c58725bfe0ff47ad3dad945c511132a1da4075ffb763d3945fb3b2f0 ]] ||
    fail "group-scoped stage probe exact-main source script differs from the reviewed executable contract"
}

extract_stage_shell_function() {
  local script="$1" function_name="$2"
  awk -v declaration="${function_name}() {" '
    $0 == declaration {in_function=1}
    in_function {print}
    in_function && $0 == "}" {exit}
  ' <<<"$script"
}

count_exact_command() {
  local file="$1" expected="$2"
  awk -v expected="$expected" '
    {line=$0; sub(/^[[:space:]]+/, "", line); sub(/[[:space:]]+$/, "", line)}
    line == expected {count++}
    END {print count + 0}
  ' "$file"
}

extract_job_if_expression() {
  local block="$1"
  awk '
    /^    if: / {
      value=$0
      sub(/^    if: /, "", value)
      if (value != ">-") {
        print value
        exit
      }
      in_if=1
      next
    }
    in_if && /^      / {
      value=$0
      sub(/^      /, "", value)
      parts[++count]=value
      next
    }
    in_if {exit}
    END {
      if (count > 0) {
        for (i=1; i<=count; i++) printf "%s%s", parts[i], (i == count ? ORS : " ")
      }
    }
  ' <<<"$block"
}

assert_exact_job_if() {
  local block="$1" expected="$2" label="$3" actual
  actual="$(extract_job_if_expression "$block")"
  [[ "$actual" == "$expected" ]] ||
    fail "$label does not have its exact probe-only reachability predicate"
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
grep -qF '          - stage-probe' "$WORKFLOW" ||
  fail "probe-only dispatch target is absent"
[[ ! -e "$STAGE_PROBE_WORKFLOW" ]] ||
  fail "obsolete separate stage probe workflow is still present"
grep -qF "artifact_digest: \${{ steps.artifact.outputs.artifact-digest }}" "$WORKFLOW" ||
  fail "build does not export the immutable artifact digest"
[[ "$(sed -n '/^permissions:/,/^env:/p' "$WORKFLOW")" == *'contents: read'* ]] ||
  fail "top-level release workflow permission is broader than read-only"
grep -qF 'install.sh is bootstrap-only' "$INSTALLER" ||
  fail "legacy installer is not guarded as first-install-only"

stage_probe_block="$(sed -n '/^  stage-readiness:/,/^  build:/p' "$WORKFLOW")"
build_block="$(sed -n '/^  build:/,/^  attach-linux-release:/p' "$WORKFLOW")"
dev_block="$(sed -n '/^  deploy-stage:/,/^  deploy-prod:/p' "$WORKFLOW")"
prod_block="$(sed -n '/^  deploy-prod:/,$p' "$WORKFLOW")"
share_block="$(sed -n '/^  deliver:/,$p' "$SHARE_WORKFLOW")"
linux_release_block="$(sed -n '/^  attach-linux-release:/,/^  build-windows-client:/p' "$WORKFLOW")"
windows_release_block="$(sed -n '/^  build-windows-client:/,/^  build-linux-client:/p' "$WORKFLOW")"
linux_client_release_block="$(sed -n '/^  build-linux-client:/,/^  build-macos-client:/p' "$WORKFLOW")"
macos_release_block="$(sed -n '/^  build-macos-client:/,/^  deploy-stage:/p' "$WORKFLOW")"
share_diff_block="$(sed -n '/name: Diff share drop-in/,/name: Install share drop-in/p' "$SHARE_WORKFLOW")"
share_install_block="$(sed -n '/name: Install share drop-in/,$p' "$SHARE_WORKFLOW")"
isolation_step="$(sed -n '/^      - name: Staging isolation capabilities$/,/^      - name: systemd version$/p' "$PROBE_WORKFLOW")"
[[ -n "$stage_probe_block" ]] || fail "inline group-scoped stage probe job is absent"
[[ "$(grep -cFx '      - name: Read-only readiness verdict' <<<"$stage_probe_block")" -eq 1 ]] ||
  fail "group-scoped stage probe job does not contain exactly one readiness step"
stage_readiness_step="$(sed -n '/^      - name: Read-only readiness verdict$/,$p' \
  <<<"$stage_probe_block")"
stage_readiness_script="$(extract_stage_readiness_script "$stage_readiness_step")"
probe_inverse="github.event_name != 'workflow_dispatch' || github.event.inputs.target != 'stage-probe'"
tag_probe_inverse="startsWith(github.ref, 'refs/tags/') && (github.event_name != 'workflow_dispatch' || github.event.inputs.target != 'stage-probe')"
assert_exact_job_if "$build_block" "$probe_inverse" "build job"
assert_exact_job_if "$linux_release_block" "$tag_probe_inverse" "Linux release attachment job"
assert_exact_job_if "$windows_release_block" "$tag_probe_inverse" "Windows client release job"
assert_exact_job_if "$linux_client_release_block" "$tag_probe_inverse" "Linux client release job"
assert_exact_job_if "$macos_release_block" "$tag_probe_inverse" "macOS client release job"
assert_exact_job_if "$dev_block" \
  "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && (github.event.inputs.target == 'stage' || github.event.inputs.target == 'prod')" \
  "staging deploy job"
assert_exact_job_if "$prod_block" \
  "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.event.inputs.target == 'prod'" \
  "production deploy job"
assert_exact_job_if "$stage_probe_block" \
  "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.event.inputs.target == 'stage-probe'" \
  "stage-readiness job"
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
  assert_unconditional_release_step "$release_block" "release attachment"
  assert_command_before "$release_block" \
    'run: bash scripts/require-fresh-main.sh "$BUILT_SHA"' \
    'uses: softprops/action-gh-release@' \
    "release attachment"
done
assert_command_before "$dev_block" \
  'bash scripts/require-fresh-main.sh "$EXPECTED_BUILD_COMMIT"' \
  'sudo -n /usr/local/sbin/disk-arcana-deploy-broker --deploy' \
  "staging broker delivery"
assert_unconditional_shell_gate_before_delivery "$dev_block" \
  'bash scripts/require-fresh-main.sh "$EXPECTED_BUILD_COMMIT"' \
  'sudo -n /usr/local/sbin/disk-arcana-deploy-broker --deploy' \
  "staging broker delivery"
assert_command_before "$prod_block" \
  'bash scripts/require-fresh-main.sh "$EXPECTED_BUILD_COMMIT"' \
  'sudo -n /usr/local/sbin/disk-arcana-deploy-broker --deploy' \
  "production broker delivery"
assert_unconditional_shell_gate_before_delivery "$prod_block" \
  'bash scripts/require-fresh-main.sh "$EXPECTED_BUILD_COMMIT"' \
  'sudo -n /usr/local/sbin/disk-arcana-deploy-broker --deploy' \
  "production broker delivery"
assert_command_before "$share_diff_block" \
  'bash scripts/require-fresh-main.sh "$GITHUB_SHA"' \
  'bash deploy/linux/install-user-share-dropin.sh' \
  "share diff"
assert_unconditional_shell_gate "$share_diff_block" \
  'bash scripts/require-fresh-main.sh "$GITHUB_SHA"' \
  "share diff"
assert_command_before "$share_install_block" \
  'bash scripts/require-fresh-main.sh "$GITHUB_SHA"' \
  'bash deploy/linux/install-user-share-dropin.sh --install' \
  "share installation"
assert_unconditional_shell_gate "$share_install_block" \
  'bash scripts/require-fresh-main.sh "$GITHUB_SHA"' \
  "share installation"

grep -qF 'default: arcana-prod' "$PROBE_WORKFLOW" || fail "INFRA-0389 default runner routing changed"
! grep -qE '^[[:space:]]*-[[:space:]]*arcana-prod-ci[[:space:]]*$' "$PROBE_WORKFLOW" ||
  fail "INFRA-0389 private-only runner leaked into the public probe"
grep -qF '[[ "${{ steps.state.outputs.unit_file_state }}" == "enabled" ]]' "$PROBE_WORKFLOW" ||
  fail "deploy probe does not require exact UnitFileState=enabled"
[[ "$isolation_step" == *'name: Staging isolation capabilities'* ]] ||
  fail "deploy probe does not collect staging isolation capabilities"
! grep -qE '^        (if|continue-on-error):' <<<"$isolation_step" ||
  fail "staging isolation capability step is conditional or non-blocking"
grep -qF 'rootless_userns="$(bool_command unshare --user --map-root-user true)"' <<<"$isolation_step" ||
  fail "deploy probe does not test an ephemeral rootless user namespace"
grep -qF 'subuid_count="$(subid_count /etc/subuid)"' <<<"$isolation_step" ||
  fail "deploy probe does not count numeric subordinate-UID allocation"
grep -qF 'subgid_count="$(subid_count /etc/subgid)"' <<<"$isolation_step" ||
  fail "deploy probe does not count numeric subordinate-GID allocation"
grep -qF '$1 == user && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {total += $3}' <<<"$isolation_step" ||
  fail "deploy probe does not validate numeric subordinate-ID records"
grep -qF '(( subuid_count >= 65536 ))' <<<"$isolation_step" ||
  fail "deploy probe does not require a usable subordinate-UID range"
grep -qF '(( subgid_count >= 65536 ))' <<<"$isolation_step" ||
  fail "deploy probe does not require a usable subordinate-GID range"
grep -qF 'user_systemd="$(bool_command systemctl --user show-environment)"' <<<"$isolation_step" ||
  fail "deploy probe does not check user-systemd availability"
grep -qF 'docker_socket_writable="$(bool_command test -w /var/run/docker.sock)"' <<<"$isolation_step" ||
  fail "deploy probe does not report host-root-equivalent Docker socket access"
grep -qF 'runner_services=unknown' <<<"$isolation_step" ||
  fail "deploy probe does not tolerate an unavailable system runner inventory"
! grep -qE '(^|[;&|])[[:space:]]*(sudo|rm|mv|cp|install|touch|mkdir|chmod|chown|setfacl|tee|truncate|mount|umount|kill|pkill|reboot|shutdown|apt|apt-get|dnf|yum|pacman|snap)[[:space:]]|systemctl[[:space:]]+(--user[[:space:]]+)?(enable|disable|start|stop|restart|reload|daemon-reload|mask|unmask|edit|link|preset)|loginctl[[:space:]]+(enable-linger|disable-linger)|(^|[;&|])[[:space:]]*(podman|docker)[[:space:]]+(run|create|start|stop|restart|rm|build|pull|push|exec)' \
    <<<"$isolation_step" || fail "read-only deploy probe contains a staging mutation"
probe_redirect_scan="$(sed -E \
  -e 's#>>"\$GITHUB_OUTPUT"([[:space:];|&)]|$)#\1#g' \
  -e 's#2?>/dev/null([[:space:];|&)]|$)#\1#g' \
  -e 's#2>&1([[:space:];|&)]|$)#\1#g' \
  <<<"$isolation_step")"
! grep -qE '<>|(^|[^<])>{1,2}([^=]|$)' <<<"$probe_redirect_scan" ||
  fail "read-only deploy probe writes outside its GitHub output"

mapfile -t release_job_keys < <(awk '
  /^jobs:$/ {in_jobs=1; next}
  in_jobs && /^  [^[:space:]#]/ {print}
' "$WORKFLOW")
expected_release_job_keys="$(printf '%s\n' \
  '  attach-linux-release:' \
  '  build:' \
  '  build-linux-client:' \
  '  build-macos-client:' \
  '  build-windows-client:' \
  '  deploy-prod:' \
  '  deploy-stage:' \
  '  stage-readiness:' | sort)"
actual_release_job_keys="$(printf '%s\n' "${release_job_keys[@]}" | sort)"
[[ "$actual_release_job_keys" == "$expected_release_job_keys" ]] ||
  fail "release workflow contains an unexpected or missing job"

! grep -qE '^    needs:' <<<"$stage_probe_block" ||
  fail "group-scoped stage probe depends on a build or delivery job"
stage_probe_permissions_count="$(awk '
  /^[[:space:]]*#/ {next}
  {
    line=$0
    sub(/[[:space:]]+#.*$/, "", line)
    gsub(/["\047]/, "", line)
    if (line ~ /^[[:space:]]*permissions[[:space:]]*:/) count++
  }
  END {print count + 0}
' <<<"$stage_probe_block")"
if [[ "$stage_probe_permissions_count" -ne 1 ]] ||
  ! grep -qFx '    permissions: {}' <<<"$stage_probe_block"; then
  fail "group-scoped stage probe permissions are not exactly empty"
fi
grep -qF 'group: disk-arcana-stage' <<<"$stage_probe_block" ||
  fail "group-scoped stage probe does not require runner group disk-arcana-stage"
grep -qF 'labels: [self-hosted, Linux, X64, disk-arcana-stage]' <<<"$stage_probe_block" ||
  fail "group-scoped stage probe does not require the exact dedicated labels"
grep -qF 'environment: staging' <<<"$stage_probe_block" ||
  fail "group-scoped stage probe does not use the staging environment"
if awk '
  /^[[:space:]]*#/ {next}
  {
    line=$0
    sub(/[[:space:]]+#.*$/, "", line)
    gsub(/["\047]/, "", line)
    if (line ~ /^[[:space:]]*(-[[:space:]]+)?uses[[:space:]]*:/ ||
        line ~ /[{,][[:space:]]*uses[[:space:]]*:/) found=1
  }
  END {exit found ? 0 : 1}
' <<<"$stage_probe_block"; then
  fail "group-scoped stage probe is not actionless"
fi
! grep -qE '^      (if|continue-on-error):' <<<"$stage_probe_block" ||
  fail "group-scoped stage probe contains a skippable or non-blocking step"

stage_probe_step_count="$(awk '
  /^    steps:$/ {in_steps=1; next}
  in_steps && /^      - / {count++}
  END {print count + 0}
' <<<"$stage_probe_block")"
[[ "$stage_probe_step_count" -eq 2 ]] ||
  fail "group-scoped stage probe must contain exactly two steps"

stage_source_guard="$(sed -n '/^      - name: Exact main source$/,/^      - name: Read-only readiness verdict$/p' \
  <<<"$stage_probe_block")"
stage_source_script="$(extract_stage_readiness_script "$stage_source_guard")"
! grep -qE '^[[:space:]]*(if|then|elif|else|case|while|until|for)[[:space:]]' \
  <<<"$stage_source_guard" ||
  fail "group-scoped stage probe exact-main guard is conditional"
grep -qFx '          [[ "$GITHUB_REF" == refs/heads/main ]]' <<<"$stage_source_guard" ||
  fail "group-scoped stage probe does not execute the exact-main guard directly"
grep -qFx '          [[ "$GITHUB_REPOSITORY" == Arcanada-one/disk-arcana ]]' \
  <<<"$stage_source_guard" ||
  fail "group-scoped stage probe does not execute the repository guard directly"
grep -qFx '          [[ "$GITHUB_WORKFLOW_REF" == Arcanada-one/disk-arcana/.github/workflows/release-deploy.yml@refs/heads/main ]]' \
  <<<"$stage_source_guard" ||
  fail "group-scoped stage probe does not execute its exact workflow-reference guard directly"
grep -qFx '          [[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]' <<<"$stage_source_guard" ||
  fail "group-scoped stage probe does not validate GITHUB_SHA as lowercase 40-hex"
grep -qFx '          [[ "$GITHUB_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]' <<<"$stage_source_guard" ||
  fail "group-scoped stage probe does not validate GITHUB_WORKFLOW_SHA as lowercase 40-hex"
grep -qFx '          [[ "$GITHUB_SHA" == "$GITHUB_WORKFLOW_SHA" ]]' <<<"$stage_source_guard" ||
  fail "group-scoped stage probe does not bind event and workflow SHAs"
assert_reviewed_stage_source_script "$stage_source_guard"
stage_probe_shell_scripts="${stage_source_script}"$'\n'"${stage_readiness_script}"

assert_direct_stage_command "$stage_readiness_step" '[[ "$(id -u)" != 0 ]]' \
  "the non-root rejection"
assert_direct_stage_command "$stage_readiness_step" '[[ " $(id -Gn) " == *" disk-arcana-deploy "* ]]' \
  "the deployment-group requirement"
assert_direct_stage_command "$stage_readiness_step" '[[ "$rootless_userns" == true ]]' \
  "the rootless-userns requirement"
assert_direct_stage_command "$stage_readiness_step" '(( subuid_count >= 65536 ))' \
  "the subordinate-UID requirement"
assert_direct_stage_command "$stage_readiness_step" '(( subgid_count >= 65536 ))' \
  "the subordinate-GID requirement"
assert_direct_stage_command "$stage_readiness_step" '[[ "$user_systemd" == true ]]' \
  "the user-systemd requirement"
assert_direct_stage_command "$stage_readiness_step" '[[ "$linger" == yes ]]' \
  "the linger requirement"
assert_direct_stage_command "$stage_readiness_step" '[[ "$podman" == true ]]' \
  "the podman requirement"
assert_direct_stage_command "$stage_readiness_step" '[[ "$docker_socket_writable" == false ]]' \
  "the writable-Docker rejection"
assert_direct_stage_command "$stage_readiness_step" '[[ "${#runner_units[@]}" -eq 1 ]]' \
  "the single-runner-unit requirement"
assert_direct_stage_command "$stage_readiness_step" '[[ "${runner_units[0]}" == actions.runner.*."${RUNNER_NAME}".service ]]' \
  "the runner-name unit binding"
assert_direct_stage_command "$stage_readiness_step" \
  'assert_active_runner_binding "${runner_units[0]}" /proc/self/cgroup' \
  "the active runner/cgroup binding"
assert_direct_stage_command "$stage_readiness_step" '[[ "${#installed_runner_units[@]}" -eq 1 ]]' \
  "the single installed runner-unit requirement"
assert_direct_stage_command "$stage_readiness_step" '[[ "${installed_runner_units[0]}" == "${runner_units[0]}" ]]' \
  "the installed/active runner-unit binding"
grep -qFx '  [[ "${#sudo_specs[@]}" -eq 1 ]]' <<<"$stage_readiness_script" ||
  fail "group-scoped stage probe lacks the single sudo-command-specification requirement"
grep -qFx '  [[ "${sudo_specs[0]}" == '\''(root) NOPASSWD: /usr/local/sbin/disk-arcana-deploy-broker --deploy *'\'' ]]' \
  <<<"$stage_readiness_script" ||
  fail "group-scoped stage probe lacks the exact narrow sudo command specification"
assert_direct_stage_command "$stage_readiness_step" 'LC_ALL=C sudo -n -l 2>/dev/null | assert_exact_sudo_policy' \
  "the exact complete sudo-policy verdict"
assert_direct_stage_command "$stage_readiness_step" '[[ -f /etc/systemd/system/disk-arcana-server.service ]]' \
  "the installed-unit requirement"
assert_direct_stage_command "$stage_readiness_step" '[[ "$(systemctl is-active disk-arcana-server 2>/dev/null)" == active ]]' \
  "the active-service requirement"
assert_direct_stage_command "$stage_readiness_step" '[[ "$(systemctl show disk-arcana-server -p UnitFileState --value 2>/dev/null)" == enabled ]]' \
  "the exact UnitFileState requirement"
assert_direct_stage_command "$stage_readiness_step" '[[ "$(systemctl show disk-arcana-server -p Restart --value 2>/dev/null)" == on-failure ]]' \
  "the Restart=on-failure requirement"
assert_direct_stage_command "$stage_readiness_step" '[[ "$(systemctl show disk-arcana-server -p StartLimitIntervalUSec --value 2>/dev/null)" == 2min ]]' \
  "the StartLimitIntervalUSec requirement"
assert_direct_stage_command "$stage_readiness_step" '[[ "$(systemctl show disk-arcana-server -p StartLimitBurst --value 2>/dev/null)" == 5 ]]' \
  "the StartLimitBurst requirement"
assert_direct_stage_command "$stage_readiness_step" \
  'curl --fail --silent --show-error --max-time 10 -o /dev/null http://127.0.0.1:9446/health' \
  "the body-suppressing health verdict"
[[ "$(grep -cF 'curl --fail' <<<"$stage_probe_block")" -eq 1 ]] ||
  fail "group-scoped stage probe contains an additional network request"
[[ "$(grep -cF 'http://127.0.0.1:9446/health' <<<"$stage_probe_block")" -eq 1 ]] ||
  fail "group-scoped stage probe health request is not loopback-only"
! grep -qE '^[[:space:]]*(ssh|scp|sftp|nc|ncat|netcat|wget|gh)[[:space:]]' \
  <<<"$stage_probe_block" || fail "group-scoped stage probe contains an external I/O command"

! grep -qE '(^|[;&|])[[:space:]]*(rm|mv|cp|install|touch|mkdir|chmod|chown|setfacl|tee|truncate|mount|umount|kill|pkill|reboot|shutdown|apt|apt-get|dnf|yum|pacman|snap)[[:space:]]|systemctl[[:space:]]+(--user[[:space:]]+)?(enable|disable|start|stop|restart|reload|daemon-reload|mask|unmask|edit|link|preset)|loginctl[[:space:]]+(enable-linger|disable-linger)|(^|[;&|])[[:space:]]*(podman|docker)[[:space:]]+(run|create|start|stop|restart|rm|build|pull|push|exec)' \
  <<<"$stage_probe_block" || fail "group-scoped stage probe contains a host mutation"
stage_probe_redirect_scan="$(sed -E \
  -e 's#2?>/dev/null([[:space:];|&)]|$)#\1#g' \
  -e 's#2>&1([[:space:];|&)]|$)#\1#g' \
  <<<"$stage_probe_shell_scripts")"
! grep -qE '<>|(^|[^<])>{1,2}([^=]|$)' <<<"$stage_probe_redirect_scan" ||
  fail "group-scoped stage probe writes to a host path"
! grep -qE '(^|[[:space:]])(env|printenv|set)[[:space:]]*($|[|;&])|/etc/(shadow|sudoers|environment)|/proc/[0-9]+/environ' \
  <<<"$stage_probe_block" || fail "group-scoped stage probe reads protected process or credential state"
! grep -qE '^[[:space:]]*(hostname|uname|systemd-analyze)([[:space:]]|$)' \
  <<<"$stage_readiness_script" || fail "group-scoped stage probe logs host identity or platform details"
! grep -qE 'runner=|runner_unit=' <<<"$stage_readiness_script" ||
  fail "group-scoped stage probe logs runner identity"
fresh_main_function="$(extract_stage_shell_function "$stage_readiness_script" assert_fresh_protected_main)"
[[ -n "$fresh_main_function" ]] ||
  fail "group-scoped stage probe lacks the verdict-time protected-main verifier"
for required_freshness_token in \
  'env -i' \
  'HOME=/nonexistent' \
  'PATH=/usr/bin:/bin' \
  'GIT_CONFIG_NOSYSTEM=1' \
  'GIT_CONFIG_GLOBAL=/dev/null' \
  'GIT_CONFIG_SYSTEM=/dev/null' \
  'GIT_CONFIG_COUNT=0' \
  'GIT_TERMINAL_PROMPT=0' \
  'GIT_ASKPASS=/bin/false' \
  'SSH_ASKPASS=/bin/false' \
  'GIT_CEILING_DIRECTORIES=/' \
  'timeout --signal=TERM --kill-after=2s 10s' \
  'git -C /' \
  '-c http.sslVerify=true' \
  '-c http.followRedirects=false' \
  '-c credential.helper=' \
  '-c core.askPass=' \
  'ls-remote --quiet --exit-code --refs' \
  'https://github.com/Arcanada-one/disk-arcana.git' \
  'refs/heads/main 2>/dev/null'; do
  grep -qF -- "$required_freshness_token" <<<"$fresh_main_function" ||
    fail "group-scoped stage probe freshness verifier lacks: $required_freshness_token"
done
[[ "$(grep -cF 'ls-remote --quiet --exit-code --refs' <<<"$fresh_main_function")" -eq 1 ]] ||
  fail "group-scoped stage probe freshness verifier does not issue exactly one remote query"
[[ "$(grep -cE '^[[:space:]]*git[[:space:]]' <<<"$fresh_main_function")" -eq 1 ]] ||
  fail "group-scoped stage probe freshness verifier does not issue exactly one Git command"
[[ "$(grep -cF 'https://github.com/Arcanada-one/disk-arcana.git' <<<"$fresh_main_function")" -eq 1 ]] ||
  fail "group-scoped stage probe freshness verifier does not use exactly one literal public URL"
[[ "$(grep -cF 'refs/heads/main 2>/dev/null' <<<"$fresh_main_function")" -eq 1 ]] ||
  fail "group-scoped stage probe freshness verifier does not use exactly one literal main ref"
grep -qF '[[ ! "$row" =~ ^([0-9a-f]{40})"${tab}"refs/heads/main$ ]]' <<<"$fresh_main_function" ||
  fail "group-scoped stage probe does not require one exact lowercase main row"
grep -qF '[[ "$live_main" == "$GITHUB_SHA" ]]' <<<"$fresh_main_function" ||
  fail "group-scoped stage probe does not compare live main to GITHUB_SHA"
grep -qF '[[ "$live_main" == "$GITHUB_WORKFLOW_SHA" ]]' <<<"$fresh_main_function" ||
  fail "group-scoped stage probe does not compare live main to GITHUB_WORKFLOW_SHA"
grep -qF 'assert_fresh_protected_main' <<<"$stage_readiness_script" ||
  fail "group-scoped stage probe does not execute the verdict-time main verifier"
readiness_tail="$(awk '
  /^assert_fresh_protected_main$/ {seen=1}
  seen && NF && $0 !~ /^#/ {print}
' <<<"$stage_readiness_script")"
[[ "$(printf '%s\n' "$readiness_tail" | sha256sum | awk '{print $1}')" == dac35c53c7890000ba0ef7663166625ea403d67130c968fd2fdcf564b01cd65f ]] ||
  fail "group-scoped stage probe freshness verifier is not immediately load-bearing on readiness"
grep -qF "printf 'readiness=ok active_runner_units=%s installed_runner_units=%s sudo_specs=1\\n'" \
  <<<"$stage_readiness_script" || fail "group-scoped stage probe lacks the bounded readiness marker"

sudo_policy_function="$(extract_stage_shell_function "$stage_readiness_script" assert_exact_sudo_policy)"
[[ -n "$sudo_policy_function" ]] ||
  fail "group-scoped stage probe does not define the exact sudo-policy parser"
sudo_policy_exact_fixture=$'Matching Defaults entries for runner on host:\n    env_reset\n\nUser runner may run the following commands on host:\n    (root) NOPASSWD: /usr/local/sbin/disk-arcana-deploy-broker --deploy *\n'
sudo_policy_broad_fixture="${sudo_policy_exact_fixture}"$'    (root) PASSWD: /bin/bash\n'
set +e
printf '%s' "$sudo_policy_exact_fixture" | bash -c \
  "set -euo pipefail
$sudo_policy_function
assert_exact_sudo_policy" >/dev/null 2>&1
sudo_policy_exact_rc=$?
printf '%s' "$sudo_policy_broad_fixture" | bash -c \
  "set -euo pipefail
$sudo_policy_function
assert_exact_sudo_policy" >/dev/null 2>&1
sudo_policy_broad_rc=$?
set -e
[[ "$sudo_policy_exact_rc" -eq 0 ]] ||
  fail "group-scoped stage probe exact broker sudo-policy fixture is rejected"
[[ "$sudo_policy_broad_rc" -ne 0 ]] ||
  fail "group-scoped stage probe accepts an additional PASSWD sudo command specification"
printf 'PASS  exact broker plus PASSWD sudo-policy fixture is rejected for the intended reason\n'

runner_binding_function="$(extract_stage_shell_function "$stage_readiness_script" assert_active_runner_binding)"
[[ -n "$runner_binding_function" ]] ||
  fail "group-scoped stage probe does not define the active runner/cgroup binding"
grep -qFx '  [[ "$(systemctl is-active "$unit" 2>/dev/null)" == active ]]' \
  <<<"$runner_binding_function" ||
  fail "group-scoped stage probe does not require the runner unit to be active"
grep -qF 'path == expected || index(path, expected "/") == 1' \
  <<<"$runner_binding_function" ||
  fail "group-scoped stage probe does not enforce the exact runner cgroup boundary"

runner_binding_fixture() {
  local state="$1" cgroup_file="$2"
  MOCK_RUNNER_STATE="$state" MOCK_RUNNER_UNIT="$runner_binding_unit" bash -c \
    "set -euo pipefail
systemctl() {
  [[ \"\$#\" -eq 2 && \"\$1\" == is-active && \"\$2\" == \"\$MOCK_RUNNER_UNIT\" ]]
  printf '%s\\n' \"\$MOCK_RUNNER_STATE\"
}
$runner_binding_function
assert_active_runner_binding \"\$MOCK_RUNNER_UNIT\" \"\$1\"" _ "$cgroup_file"
}

runner_binding_unit='actions.runner.Arcanada-one-disk-arcana.stage.service'
runner_binding_fixture_root="$(mktemp -d)"
trap 'rm -rf -- "$runner_binding_fixture_root"' EXIT
runner_cgroup_exact="$runner_binding_fixture_root/exact"
runner_cgroup_descendant="$runner_binding_fixture_root/descendant"
runner_cgroup_collision="$runner_binding_fixture_root/collision"
printf '0::/system.slice/%s\n' "$runner_binding_unit" >"$runner_cgroup_exact"
printf '0::/system.slice/%s/runner-worker.scope\n' "$runner_binding_unit" >"$runner_cgroup_descendant"
printf '0::/system.slice/%s.attacker.scope\n' "$runner_binding_unit" >"$runner_cgroup_collision"

runner_binding_fixture active "$runner_cgroup_exact" >/dev/null 2>&1 ||
  fail "group-scoped stage probe rejects the exact active runner cgroup fixture"
runner_binding_fixture active "$runner_cgroup_descendant" >/dev/null 2>&1 ||
  fail "group-scoped stage probe rejects the active runner cgroup descendant fixture"
set +e
runner_binding_fixture inactive "$runner_cgroup_exact" >/dev/null 2>&1
inactive_runner_rc=$?
runner_binding_fixture active "$runner_cgroup_collision" >/dev/null 2>&1
runner_cgroup_collision_rc=$?
set -e
[[ "$inactive_runner_rc" -ne 0 ]] ||
  fail "group-scoped stage probe accepts an inactive runner service"
[[ "$runner_cgroup_collision_rc" -ne 0 ]] ||
  fail "group-scoped stage probe accepts a runner cgroup prefix collision"
printf 'PASS  inactive runner service is rejected for the intended reason\n'
printf 'PASS  runner .service.attacker.scope cgroup collision is rejected for the intended reason\n'
rm -rf -- "$runner_binding_fixture_root"
trap - EXIT
assert_reviewed_stage_readiness_script "$stage_readiness_step"

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

  run_source_guard_fixture() {
    local event_sha="$1" workflow_sha="$2" expected_rc="$3" actual_rc
    set +e
    GITHUB_REF=refs/heads/main \
      GITHUB_REPOSITORY=Arcanada-one/disk-arcana \
      GITHUB_WORKFLOW_REF=Arcanada-one/disk-arcana/.github/workflows/release-deploy.yml@refs/heads/main \
      GITHUB_SHA="$event_sha" \
      GITHUB_WORKFLOW_SHA="$workflow_sha" \
      bash -c "set -euo pipefail
$stage_source_script" >/dev/null 2>&1
    actual_rc=$?
    set -e
    [[ "$actual_rc" -eq "$expected_rc" ]] ||
      fail "exact-main source SHA fixture returned $actual_rc instead of $expected_rc"
  }

  source_guard_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  run_source_guard_fixture "$source_guard_sha" "$source_guard_sha" 0
  run_source_guard_fixture AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "$source_guard_sha" 1
  run_source_guard_fixture aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$source_guard_sha" 1
  run_source_guard_fixture "$source_guard_sha" AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1
  run_source_guard_fixture "$source_guard_sha" bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 1
  printf 'PASS  exact-main source guard rejects malformed and mismatched SHAs\n'

  freshness_fixture_bin="$fixture_root/freshness-bin"
  freshness_fixture_mode="$fixture_root/freshness-mode"
  mkdir -p "$freshness_fixture_bin"
  ln -s /usr/bin/timeout "$freshness_fixture_bin/timeout"
  read -r -d '' freshness_fake_git <<'FAKE_GIT' || true
#!/usr/bin/env bash
set -euo pipefail

expected_args=(
  -C /
  -c http.sslVerify=true
  -c http.followRedirects=false
  -c credential.helper=
  -c core.askPass=
  ls-remote --quiet --exit-code --refs
  https://github.com/Arcanada-one/disk-arcana.git
  refs/heads/main
)
[[ "$#" -eq "${#expected_args[@]}" ]] || {
  printf 'FAKE_GIT_ARGUMENT_CANARY\n' >&2
  exit 90
}
for ((argument_index = 0; argument_index < ${#expected_args[@]}; argument_index++)); do
  argument_position=$((argument_index + 1))
  [[ "${!argument_position}" == "${expected_args[argument_index]}" ]] || {
    printf 'FAKE_GIT_ARGUMENT_CANARY\n' >&2
    exit 90
  }
done
[[ "$HOME" == /nonexistent ]]
[[ "$LC_ALL" == C ]]
[[ "$GIT_CONFIG_NOSYSTEM" == 1 ]]
[[ "$GIT_CONFIG_GLOBAL" == /dev/null ]]
[[ "$GIT_CONFIG_SYSTEM" == /dev/null ]]
[[ "$GIT_CONFIG_COUNT" == 0 ]]
[[ "$GIT_TERMINAL_PROMPT" == 0 ]]
[[ "$GIT_ASKPASS" == /bin/false ]]
[[ "$SSH_ASKPASS" == /bin/false ]]
[[ "$GIT_CEILING_DIRECTORIES" == / ]]
for forbidden_name in \
  GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_CONFIG_PARAMETERS \
  GIT_SSL_NO_VERIFY GIT_SSL_CAINFO GIT_EXEC_PATH GIT_CURL_VERBOSE \
  GIT_TRACE GIT_TRACE2; do
  [[ -z "${!forbidden_name+x}" ]] || {
    printf 'FAKE_GIT_ENVIRONMENT_CANARY\n' >&2
    exit 91
  }
done

case "$(<__MODE_FILE__)" in
  success)
    printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/heads/main\n'
    ;;
  stale)
    printf 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/heads/main\n'
    ;;
  empty)
    ;;
  multiple)
    printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/heads/main\n'
    printf 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/heads/main\n'
    ;;
  malformed)
    printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\trefs/heads/main\n'
    ;;
  wrong-ref)
    printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/heads/not-main\n'
    ;;
  failure)
    printf 'FAKE_QUERY_STDOUT_CANARY\n'
    printf 'FAKE_QUERY_STDERR_CANARY\n' >&2
    exit 92
    ;;
  timeout)
    sleep 2
    printf 'FAKE_QUERY_TIMEOUT_CANARY\n'
    ;;
  *)
    exit 93
    ;;
esac
FAKE_GIT
  printf '%s\n' "$freshness_fake_git" >"$freshness_fixture_bin/git"
  sed -i "s#__MODE_FILE__#$freshness_fixture_mode#" "$freshness_fixture_bin/git"
  chmod 0700 "$freshness_fixture_bin/git"
  fresh_main_fixture_function="$(
    sed \
      -e "s#PATH=/usr/bin:/bin#PATH=$freshness_fixture_bin:/usr/bin:/bin#" \
      -e 's#timeout --signal=TERM --kill-after=2s 10s#timeout --signal=TERM --kill-after=0.1s 0.2s#' \
      <<<"$fresh_main_function"
  )"

  run_freshness_fixture() {
    local mode="$1" event_sha="$2" workflow_sha="$3" expected_rc="$4" expected_output="$5"
    local actual_output actual_rc
    printf '%s\n' "$mode" >"$freshness_fixture_mode"
    set +e
    actual_output="$(
      GITHUB_SHA="$event_sha" \
      GITHUB_WORKFLOW_SHA="$workflow_sha" \
      GIT_DIR=EVENT_GIT_DIR_CANARY \
      GIT_WORK_TREE=EVENT_GIT_WORK_TREE_CANARY \
      GIT_CONFIG_PARAMETERS=EVENT_GIT_CONFIG_CANARY \
      GIT_SSL_NO_VERIFY=EVENT_GIT_SSL_CANARY \
      GIT_TRACE=EVENT_GIT_TRACE_CANARY \
      bash -c "set -euo pipefail
$fresh_main_fixture_function
assert_fresh_protected_main" 2>&1
    )"
    actual_rc=$?
    set -e
    [[ "$actual_rc" -eq "$expected_rc" ]] ||
      fail "verdict-time main fixture $mode returned $actual_rc instead of $expected_rc"
    [[ "$actual_output" == "$expected_output" ]] ||
      fail "verdict-time main fixture $mode emitted an unbounded or incorrect verdict"
  }

  freshness_live_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  freshness_other_sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  run_freshness_fixture success "$freshness_live_sha" "$freshness_live_sha" 0 ''
  run_freshness_fixture stale "$freshness_live_sha" "$freshness_live_sha" 1 \
    'freshness=fail reason=stale-main'
  run_freshness_fixture success "$freshness_live_sha" "$freshness_other_sha" 1 \
    'freshness=fail reason=workflow-sha'
  run_freshness_fixture empty "$freshness_live_sha" "$freshness_live_sha" 1 \
    'freshness=fail reason=row-shape'
  run_freshness_fixture multiple "$freshness_live_sha" "$freshness_live_sha" 1 \
    'freshness=fail reason=row-count'
  run_freshness_fixture malformed "$freshness_live_sha" "$freshness_live_sha" 1 \
    'freshness=fail reason=row-shape'
  run_freshness_fixture wrong-ref "$freshness_live_sha" "$freshness_live_sha" 1 \
    'freshness=fail reason=row-shape'
  run_freshness_fixture failure "$freshness_live_sha" "$freshness_live_sha" 1 \
    'freshness=fail reason=query'
  run_freshness_fixture timeout "$freshness_live_sha" "$freshness_live_sha" 1 \
    'freshness=fail reason=query'
  printf 'PASS  verdict-time main verifier fails closed with isolated bounded output\n'

  run_release_fixture() {
    local workflow="$1" expected="$2" label="$3" fixture_rc
    set +e
    DISK_ARCANA_ORDER_FIXTURE_CHILD=1 \
      WORKFLOW_OVERRIDE="$workflow" \
      SHARE_WORKFLOW_OVERRIDE="$SHARE_WORKFLOW" \
      PROBE_WORKFLOW_OVERRIDE="$PROBE_WORKFLOW" \
      "$0" >"$fixture_output" 2>&1
    fixture_rc=$?
    set -e
    [[ "$fixture_rc" -ne 0 ]] || fail "$label fixture passed"
    grep -qF "$expected" "$fixture_output" || fail "$label fixture failed for an unintended reason"
  }

  run_probe_fixture() {
    local probe="$1" expected="$2" label="$3" fixture_rc
    set +e
    DISK_ARCANA_ORDER_FIXTURE_CHILD=1 \
      WORKFLOW_OVERRIDE="$WORKFLOW" \
      SHARE_WORKFLOW_OVERRIDE="$SHARE_WORKFLOW" \
      PROBE_WORKFLOW_OVERRIDE="$probe" \
      "$0" >"$fixture_output" 2>&1
    fixture_rc=$?
    set -e
    [[ "$fixture_rc" -ne 0 ]] || fail "$label fixture passed"
    grep -qF "$expected" "$fixture_output" || fail "$label fixture failed for an unintended reason"
  }

  run_stage_probe_fixture() {
    local stage_probe="$1" expected="$2" label="$3" fixture_rc
    set +e
    DISK_ARCANA_ORDER_FIXTURE_CHILD=1 \
      WORKFLOW_OVERRIDE="$stage_probe" \
      SHARE_WORKFLOW_OVERRIDE="$SHARE_WORKFLOW" \
      PROBE_WORKFLOW_OVERRIDE="$PROBE_WORKFLOW" \
      "$0" >"$fixture_output" 2>&1
    fixture_rc=$?
    set -e
    [[ "$fixture_rc" -ne 0 ]] || fail "$label fixture passed"
    grep -qF "$expected" "$fixture_output" || fail "$label fixture failed for an unintended reason"
  }

  missing_event_sha_guard="$fixture_root/stage-probe-missing-event-sha-guard.yml"
  grep -vF '          [[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]' \
    "$WORKFLOW" >"$missing_event_sha_guard"
  run_stage_probe_fixture "$missing_event_sha_guard" \
    'FAIL  group-scoped stage probe does not validate GITHUB_SHA as lowercase 40-hex' \
    "missing event SHA format guard"
  printf 'PASS  missing event SHA format guard is rejected for the intended reason\n'

  missing_workflow_sha_guard="$fixture_root/stage-probe-missing-workflow-sha-guard.yml"
  grep -vF '          [[ "$GITHUB_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]' \
    "$WORKFLOW" >"$missing_workflow_sha_guard"
  run_stage_probe_fixture "$missing_workflow_sha_guard" \
    'FAIL  group-scoped stage probe does not validate GITHUB_WORKFLOW_SHA as lowercase 40-hex' \
    "missing workflow SHA format guard"
  printf 'PASS  missing workflow SHA format guard is rejected for the intended reason\n'

  missing_sha_binding="$fixture_root/stage-probe-missing-sha-binding.yml"
  grep -vF '          [[ "$GITHUB_SHA" == "$GITHUB_WORKFLOW_SHA" ]]' \
    "$WORKFLOW" >"$missing_sha_binding"
  run_stage_probe_fixture "$missing_sha_binding" \
    'FAIL  group-scoped stage probe does not bind event and workflow SHAs' \
    "missing event/workflow SHA binding"
  printf 'PASS  missing event/workflow SHA binding is rejected for the intended reason\n'

  missing_environment_isolation="$fixture_root/stage-probe-missing-config-isolation.yml"
  grep -vF "                GIT_CONFIG_NOSYSTEM=1 \\" \
    "$WORKFLOW" >"$missing_environment_isolation"
  run_stage_probe_fixture "$missing_environment_isolation" \
    'FAIL  group-scoped stage probe freshness verifier lacks: GIT_CONFIG_NOSYSTEM=1' \
    "missing Git system-config isolation"
  printf 'PASS  missing Git system-config isolation is rejected for the intended reason\n'

  second_remote_query="$fixture_root/stage-probe-second-remote-query.yml"
  awk '
    !mutated && /^              env -i \\$/ {
      print "              git ls-remote https://example.invalid refs/heads/main"
      mutated=1
    }
    {print}
  ' "$WORKFLOW" >"$second_remote_query"
  run_stage_probe_fixture "$second_remote_query" \
    'FAIL  group-scoped stage probe freshness verifier does not issue exactly one Git command' \
    "additional off-host Git query"
  printf 'PASS  additional off-host Git query is rejected for the intended reason\n'

  inert_freshness_call="$fixture_root/stage-probe-inert-freshness-call.yml"
  awk '
    !mutated && /^          assert_fresh_protected_main$/ {
      print "          if false; then"
      print "            assert_fresh_protected_main"
      print "          fi"
      mutated=1
      next
    }
    {print}
  ' "$WORKFLOW" >"$inert_freshness_call"
  run_stage_probe_fixture "$inert_freshness_call" \
    'FAIL  group-scoped stage probe freshness verifier is not immediately load-bearing on readiness' \
    "inert verdict-time freshness call"
  printf 'PASS  inert verdict-time freshness call is rejected for the intended reason\n'

  reordered_freshness_call="$fixture_root/stage-probe-reordered-freshness-call.yml"
  awk '
    !mutated && /^          assert_fresh_protected_main$/ {
      held=$0
      mutated=1
      next
    }
    mutated && !inserted && /^            "\$\{#runner_units\[@\]\}"/ {
      print
      print held
      inserted=1
      next
    }
    {print}
  ' "$WORKFLOW" >"$reordered_freshness_call"
  run_stage_probe_fixture "$reordered_freshness_call" \
    'FAIL  group-scoped stage probe freshness verifier is not immediately load-bearing on readiness' \
    "freshness call after readiness marker"
  printf 'PASS  post-readiness freshness call is rejected for the intended reason\n'

  write_probe_reachable_job_fixture() {
    local job="$1" output="$2"
    awk -v target="$job" '
      /^  [A-Za-z0-9_-]+:$/ {
        line=$0
        sub(/^[[:space:]]+/, "", line)
        in_target=(line == target ":")
      }
      skip_if && /^      / {next}
      skip_if {skip_if=0}
      in_target && !mutated && /^    if: / {
        print "    if: github.event_name == '\''workflow_dispatch'\'' && github.event.inputs.target == '\''stage-probe'\''"
        if ($0 ~ />-[[:space:]]*$/) skip_if=1
        mutated=1
        next
      }
      {print}
    ' "$WORKFLOW" >"$output"
  }

  for reachability_case in \
    'build|build job' \
    'attach-linux-release|Linux release attachment job' \
    'build-windows-client|Windows client release job' \
    'build-linux-client|Linux client release job' \
    'build-macos-client|macOS client release job' \
    'deploy-stage|staging deploy job' \
    'deploy-prod|production deploy job'; do
    reachability_job="${reachability_case%%|*}"
    reachability_label="${reachability_case#*|}"
    reachable_workflow="$fixture_root/release-${reachability_job}-admits-stage-probe.yml"
    write_probe_reachable_job_fixture "$reachability_job" "$reachable_workflow"
    run_release_fixture "$reachable_workflow" \
      "FAIL  $reachability_label does not have its exact probe-only reachability predicate" \
      "$reachability_label admitting stage-probe"
    printf 'PASS  %s cannot admit probe-only dispatch\n' "$reachability_label"
  done

  disabled_release="$fixture_root/release-disabled-gate.yml"
  awk '
    {
      line=$0
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
    }
    !mutated && line == "- name: Fresh exact-main release gate" {
      print
      match($0, /[^ ]/)
      print substr($0, 1, RSTART - 1) "  if: false"
      mutated=1
      next
    }
    {print}
  ' "$WORKFLOW" >"$disabled_release"
  run_release_fixture "$disabled_release" \
    'FAIL  release attachment freshness step is conditional or non-blocking' \
    "disabled release freshness"
  printf 'PASS  disabled release freshness step is rejected as non-load-bearing\n'

  write_conditional_broker_fixture() {
    local job="$1" output="$2"
    awk -v target="$job" '
      /^  [A-Za-z0-9_-]+:$/ {
        line=$0
        sub(/^[[:space:]]+/, "", line)
        in_target=(line == target ":")
      }
      in_target && index($0, "bash scripts/require-fresh-main.sh \"$EXPECTED_BUILD_COMMIT\"") {
        match($0, /[^ ]/)
        prefix=substr($0, 1, RSTART - 1)
        print prefix "if false; then"
        print "  " $0
        print prefix "fi"
        next
      }
      {print}
    ' "$WORKFLOW" >"$output"
  }

  conditional_stage="$fixture_root/release-conditional-stage-gate.yml"
  write_conditional_broker_fixture deploy-stage "$conditional_stage"
  run_release_fixture "$conditional_stage" \
    'FAIL  staging broker delivery freshness gate is not unconditional or load-bearing' \
    "conditional staging freshness"
  printf 'PASS  branch-local staging freshness command is rejected as non-load-bearing\n'

  conditional_prod="$fixture_root/release-conditional-prod-gate.yml"
  write_conditional_broker_fixture deploy-prod "$conditional_prod"
  run_release_fixture "$conditional_prod" \
    'FAIL  production broker delivery freshness gate is not unconditional or load-bearing' \
    "conditional production freshness"
  printf 'PASS  branch-local production freshness command is rejected as non-load-bearing\n'

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

  conditional_share="$fixture_root/share-conditional-gate.yml"
  sed '/name: Install share drop-in/,$ {
    /bash scripts\/require-fresh-main.sh "$GITHUB_SHA"/{s/^/  /;h;d}
    /if \[\[ "$(id -un)" == dev \]\]; then/G
  }' "$SHARE_WORKFLOW" >"$conditional_share"
  set +e
  DISK_ARCANA_ORDER_FIXTURE_CHILD=1 \
    WORKFLOW_OVERRIDE="$WORKFLOW" \
    SHARE_WORKFLOW_OVERRIDE="$conditional_share" \
    PROBE_WORKFLOW_OVERRIDE="$PROBE_WORKFLOW" \
    "$0" >"$fixture_output" 2>&1
  fixture_rc=$?
  set -e
  [[ "$fixture_rc" -ne 0 ]] || fail "conditional share freshness fixture passed"
  grep -qF 'FAIL  share installation freshness gate is not unconditional' "$fixture_output" ||
    fail "conditional share freshness fixture failed for an unintended reason"
  printf 'PASS  branch-local share freshness command is rejected as a conditional gate\n'

  short_circuit_share="$fixture_root/share-short-circuit-gate.yml"
  awk '
    index($0, "name: Install share drop-in") {install_step=1}
    install_step && index($0, "bash scripts/require-fresh-main.sh") {
      gate=$0
      next
    }
    install_step && index($0, "if [[ \"$(id -un)\" == dev ]]; then") {
      match($0, /[^ ]/)
      print substr($0, 1, RSTART - 1) "[[ \"$(id -un)\" == dev ]] && {"
      print gate
      in_short_circuit=1
      next
    }
    in_short_circuit {
      line=$0
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
      if (line == "fi") {
        sub(/fi[[:space:]]*$/, "}")
        in_short_circuit=0
      }
    }
    {print}
  ' "$SHARE_WORKFLOW" >"$short_circuit_share"
  set +e
  DISK_ARCANA_ORDER_FIXTURE_CHILD=1 \
    WORKFLOW_OVERRIDE="$WORKFLOW" \
    SHARE_WORKFLOW_OVERRIDE="$short_circuit_share" \
    PROBE_WORKFLOW_OVERRIDE="$PROBE_WORKFLOW" \
    "$0" >"$fixture_output" 2>&1
  fixture_rc=$?
  set -e
  [[ "$fixture_rc" -ne 0 ]] || fail "short-circuit share freshness fixture passed"
  grep -qF 'FAIL  share installation freshness gate is not unconditional' "$fixture_output" ||
    fail "short-circuit share freshness fixture failed for an unintended reason"
  printf 'PASS  short-circuit share freshness command is rejected as a conditional gate\n'

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

  disabled_probe="$fixture_root/probe-disabled-isolation.yml"
  awk '
    !mutated && /^      - name: Staging isolation capabilities$/ {
      print
      print "        if: false"
      mutated=1
      next
    }
    {print}
  ' "$PROBE_WORKFLOW" >"$disabled_probe"
  run_probe_fixture "$disabled_probe" \
    'FAIL  staging isolation capability step is conditional or non-blocking' \
    "disabled staging capability"
  printf 'PASS  disabled staging capability step is rejected as non-load-bearing\n'

  missing_subgid="$fixture_root/probe-missing-subgid.yml"
  sed '/subgid_count="$(subid_count \/etc\/subgid)"/d' "$PROBE_WORKFLOW" >"$missing_subgid"
  run_probe_fixture "$missing_subgid" \
    'FAIL  deploy probe does not count numeric subordinate-GID allocation' \
    "missing subordinate-GID probe"
  printf 'PASS  missing subordinate-GID probe is rejected for the intended reason\n'

  mutating_probe="$fixture_root/probe-systemd-mutation.yml"
  sed '/user_systemd="$(bool_command systemctl --user show-environment)"/a\          systemctl restart disk-arcana-stage.service' \
    "$PROBE_WORKFLOW" >"$mutating_probe"
  run_probe_fixture "$mutating_probe" \
    'FAIL  read-only deploy probe contains a staging mutation' \
    "system-systemd mutation"
  printf 'PASS  system-systemd mutation is rejected for the intended reason\n'

  writing_probe="$fixture_root/probe-host-write.yml"
  sed '/user_systemd="$(bool_command systemctl --user show-environment)"/a\          true >/dev/null; printf mutated >disk-arcana-stage-probe-mutant' \
    "$PROBE_WORKFLOW" >"$writing_probe"
  run_probe_fixture "$writing_probe" \
    'FAIL  read-only deploy probe writes outside its GitHub output' \
    "host write"
  printf 'PASS  host-write mutation is rejected for the intended reason\n'

  read_write_probe="$fixture_root/probe-read-write-redirection.yml"
  sed '/user_systemd="$(bool_command systemctl --user show-environment)"/a\          exec 3<>disk-arcana-stage-probe-mutant' \
    "$PROBE_WORKFLOW" >"$read_write_probe"
  run_probe_fixture "$read_write_probe" \
    'FAIL  read-only deploy probe writes outside its GitHub output' \
    "read-write redirection"
  printf 'PASS  read-write redirection is rejected for the intended reason\n'

  suffix_write_probe="$fixture_root/probe-output-suffix-write.yml"
  sed '/user_systemd="$(bool_command systemctl --user show-environment)"/a\          printf mutated >>"$GITHUB_OUTPUT".bak' \
    "$PROBE_WORKFLOW" >"$suffix_write_probe"
  run_probe_fixture "$suffix_write_probe" \
    'FAIL  read-only deploy probe writes outside its GitHub output' \
    "GitHub-output suffix write"
  printf 'PASS  GitHub-output suffix write is rejected for the intended reason\n'

  labels_only_stage_probe="$fixture_root/stage-probe-labels-only.yml"
  sed '/^  stage-readiness:$/,/^  build:$/ {/^[[:space:]]*group: disk-arcana-stage$/d
  }' \
    "$WORKFLOW" >"$labels_only_stage_probe"
  run_stage_probe_fixture "$labels_only_stage_probe" \
    'FAIL  group-scoped stage probe does not require runner group disk-arcana-stage' \
    "labels-only stage probe"
  printf 'PASS  labels-only stage probe is rejected for the intended reason\n'

  wrong_group_stage_probe="$fixture_root/stage-probe-wrong-group.yml"
  sed '/^  stage-readiness:$/,/^  build:$/ {s/group: disk-arcana-stage/group: ci-general/
  }' \
    "$WORKFLOW" >"$wrong_group_stage_probe"
  run_stage_probe_fixture "$wrong_group_stage_probe" \
    'FAIL  group-scoped stage probe does not require runner group disk-arcana-stage' \
    "wrong runner group"
  printf 'PASS  wrong runner group is rejected for the intended reason\n'

  job_permissions_stage_probe="$fixture_root/stage-probe-job-permissions.yml"
  sed '/^  stage-readiness:$/a\    permissions: write-all' \
    "$WORKFLOW" >"$job_permissions_stage_probe"
  run_stage_probe_fixture "$job_permissions_stage_probe" \
    'FAIL  group-scoped stage probe permissions are not exactly empty' \
    "job-level write-all permissions"
  printf 'PASS  job-level write-all permissions are rejected for the intended reason\n'

  flow_action_stage_probe="$fixture_root/stage-probe-flow-action.yml"
  sed '/^  stage-readiness:$/,/^  build:$/ {/^[[:space:]]*steps:$/a\      - {uses: actions/checkout@0000000000000000000000000000000000000000}
  }' "$WORKFLOW" >"$flow_action_stage_probe"
  run_stage_probe_fixture "$flow_action_stage_probe" \
    'FAIL  group-scoped stage probe is not actionless' \
    "flow-style stage probe action step"
  printf 'PASS  flow-style action step is rejected for the intended reason\n'

  action_stage_probe="$fixture_root/stage-probe-action.yml"
  sed '/^  stage-readiness:$/,/^  build:$/ {/^[[:space:]]*steps:$/a\      - uses: actions/checkout@0000000000000000000000000000000000000000
  }' "$WORKFLOW" >"$action_stage_probe"
  run_stage_probe_fixture "$action_stage_probe" \
    'FAIL  group-scoped stage probe is not actionless' \
    "stage probe action step"
  printf 'PASS  separate block-style action step is rejected for the intended reason\n'

  raw_sudo_step_stage_probe="$fixture_root/stage-probe-raw-sudo-step.yml"
  sed '/^  stage-readiness:$/,/^  build:$/ {/^[[:space:]]*steps:$/a\      - name: Raw sudo policy outside readiness\
        shell: bash\
        run: sudo -n -l
  }' "$WORKFLOW" >"$raw_sudo_step_stage_probe"
  run_stage_probe_fixture "$raw_sudo_step_stage_probe" \
    'FAIL  group-scoped stage probe must contain exactly two steps' \
    "separate raw sudo policy step"
  printf 'PASS  separate raw sudo policy step is rejected for the intended reason\n'

  host_write_step_stage_probe="$fixture_root/stage-probe-dd-host-write-step.yml"
  sed '/^  stage-readiness:$/,/^  build:$/ {/^[[:space:]]*steps:$/a\      - name: Host write outside readiness\
        shell: bash\
        run: dd if=/dev/zero of=/tmp/disk-arcana-stage-probe-mutant bs=1 count=1
  }' "$WORKFLOW" >"$host_write_step_stage_probe"
  run_stage_probe_fixture "$host_write_step_stage_probe" \
    'FAIL  group-scoped stage probe must contain exactly two steps' \
    "separate dd host-write step"
  printf 'PASS  separate dd host-write step is rejected for the intended reason\n'

  disabled_stage_probe="$fixture_root/stage-probe-disabled-job.yml"
  sed "s/github.event.inputs.target == 'stage-probe'/false/" \
    "$WORKFLOW" >"$disabled_stage_probe"
  run_stage_probe_fixture "$disabled_stage_probe" \
    'FAIL  stage-readiness job does not have its exact probe-only reachability predicate' \
    "disabled stage-readiness job"
  printf 'PASS  disabled stage-readiness job is rejected for the intended reason\n'

  extra_job_stage_probe="$fixture_root/stage-probe-extra-job.yml"
  awk '
    {print}
    END {
      print ""
      print "  mutate-stage-host:"
      print "    runs-on:"
      print "      group: disk-arcana-stage"
      print "      labels: [self-hosted, Linux, X64, disk-arcana-stage]"
      print "    steps:"
      print "      - name: Mutate outside the reviewed probe job"
      print "        shell: bash"
      print "        run: touch /tmp/disk-arcana-stage-probe-mutant"
    }
  ' "$WORKFLOW" >"$extra_job_stage_probe"
  run_stage_probe_fixture "$extra_job_stage_probe" \
    'FAIL  release workflow contains an unexpected or missing job' \
    "additional mutating stage job"
  printf 'PASS  additional mutating stage job is rejected for the intended reason\n'

  quoted_job_stage_probe="$fixture_root/stage-probe-quoted-extra-job.yml"
  awk '
    /^  stage-readiness:$/ && !inserted {
      print "  \"mutate-stage-host\":"
      print "    runs-on:"
      print "      group: disk-arcana-stage"
      print "      labels: [self-hosted, Linux, X64, disk-arcana-stage]"
      print "    steps:"
      print "      - shell: bash"
      print "        run: touch /tmp/disk-arcana-stage-probe-mutant"
      inserted=1
    }
    {print}
  ' "$WORKFLOW" >"$quoted_job_stage_probe"
  run_stage_probe_fixture "$quoted_job_stage_probe" \
    'FAIL  release workflow contains an unexpected or missing job' \
    "quoted additional mutating stage job"
  printf 'PASS  quoted additional mutating stage job is rejected for the intended reason\n'

  merge_job_stage_probe="$fixture_root/stage-probe-merge-extra-job.yml"
  sed '/^  stage-readiness:$/i\  <<: *mutating-stage-job' \
    "$WORKFLOW" >"$merge_job_stage_probe"
  run_stage_probe_fixture "$merge_job_stage_probe" \
    'FAIL  release workflow contains an unexpected or missing job' \
    "merge-key additional stage job"
  printf 'PASS  merge-key additional stage job is rejected for the intended reason\n'

  explicit_job_stage_probe="$fixture_root/stage-probe-explicit-extra-job.yml"
  sed '/^  stage-readiness:$/i\  ? mutate-stage-host\
  : {runs-on: ubuntu-latest, steps: [{run: touch /tmp/disk-arcana-stage-probe-mutant}]}' \
    "$WORKFLOW" >"$explicit_job_stage_probe"
  run_stage_probe_fixture "$explicit_job_stage_probe" \
    'FAIL  release workflow contains an unexpected or missing job' \
    "explicit-key additional stage job"
  printf 'PASS  explicit-key additional stage job is rejected for the intended reason\n'

  flow_job_stage_probe="$fixture_root/stage-probe-flow-extra-job.yml"
  sed '/^  stage-readiness:$/i\  mutate-stage-host: {runs-on: ubuntu-latest, steps: [{run: touch /tmp/disk-arcana-stage-probe-mutant}]}' \
    "$WORKFLOW" >"$flow_job_stage_probe"
  run_stage_probe_fixture "$flow_job_stage_probe" \
    'FAIL  release workflow contains an unexpected or missing job' \
    "flow-form additional stage job"
  printf 'PASS  flow-form additional stage job is rejected for the intended reason\n'

  conditional_main_stage_probe="$fixture_root/stage-probe-conditional-main.yml"
  awk '
    !mutated && index($0, "[[ \"$GITHUB_REF\" == refs/heads/main ]]") {
      match($0, /[^ ]/)
      prefix=substr($0, 1, RSTART - 1)
      print prefix "if false; then"
      print "  " $0
      print prefix "fi"
      mutated=1
      next
    }
    {print}
  ' "$WORKFLOW" >"$conditional_main_stage_probe"
  run_stage_probe_fixture "$conditional_main_stage_probe" \
    'FAIL  group-scoped stage probe exact-main guard is conditional' \
    "conditional exact-main guard"
  printf 'PASS  conditional exact-main guard is rejected for the intended reason\n'

  early_exit_main_stage_probe="$fixture_root/stage-probe-early-exit-main.yml"
  awk '
    !mutated && /^          set -euo pipefail$/ {
      print
      print "          exit 0"
      mutated=1
      next
    }
    {print}
  ' "$WORKFLOW" >"$early_exit_main_stage_probe"
  run_stage_probe_fixture "$early_exit_main_stage_probe" \
    'FAIL  group-scoped stage probe exact-main source script differs from the reviewed executable contract' \
    "early-success exit in exact-main source"
  printf 'PASS  early-success exit in exact-main source is rejected for the intended reason\n'

  early_return_main_stage_probe="$fixture_root/stage-probe-early-return-main.yml"
  awk '
    !mutated && /^          set -euo pipefail$/ {
      print
      print "          return 0"
      mutated=1
      next
    }
    {print}
  ' "$WORKFLOW" >"$early_return_main_stage_probe"
  run_stage_probe_fixture "$early_return_main_stage_probe" \
    'FAIL  group-scoped stage probe exact-main source script differs from the reviewed executable contract' \
    "early-success return in exact-main source"
  printf 'PASS  early-success return in exact-main source is rejected for the intended reason\n'

  inert_main_stage_probe="$fixture_root/stage-probe-inert-main-function.yml"
  awk '
    !mutated && index($0, "[[ \"$GITHUB_REF\" == refs/heads/main ]]") {
      match($0, /[^ ]/)
      prefix=substr($0, 1, RSTART - 1)
      print prefix "source_guard() {"
      print "  " $0
      in_guard=1
      mutated=1
      next
    }
    in_guard && index($0, "[[ \"$GITHUB_WORKFLOW_REF\"") {
      print "  " $0
      print prefix "}"
      in_guard=0
      next
    }
    in_guard {print "  " $0; next}
    {print}
  ' "$WORKFLOW" >"$inert_main_stage_probe"
  run_stage_probe_fixture "$inert_main_stage_probe" \
    'FAIL  group-scoped stage probe does not execute the exact-main guard directly' \
    "inert exact-main function"
  printf 'PASS  inert exact-main function is rejected for the intended reason\n'

  inert_readiness_stage_probe="$fixture_root/stage-probe-inert-readiness-function.yml"
  awk '
    /^          \[\[ "\$rootless_userns" == true \]\]$/ && !mutated {
      print "          readiness_assertions() {"
      print $0
      in_assertions=1
      mutated=1
      next
    }
    in_assertions && index($0, "assert_active_runner_binding \"${runner_units[0]}\" /proc/self/cgroup") {
      print $0
      print "          }"
      in_assertions=0
      next
    }
    {print}
  ' "$WORKFLOW" >"$inert_readiness_stage_probe"
  inert_readiness_script="$(sed -n '/^      - name: Read-only readiness verdict$/,$p' \
    "$inert_readiness_stage_probe")"
  bash -n -s <<<"$(extract_stage_readiness_script "$inert_readiness_script")" ||
    fail "inert readiness function fixture is not valid Bash"
  run_stage_probe_fixture "$inert_readiness_stage_probe" \
    'FAIL  group-scoped stage probe readiness script differs from the reviewed executable contract' \
    "inert readiness function"
  printf 'PASS  inert readiness function is rejected for the intended reason\n'

  short_circuit_readiness_stage_probe="$fixture_root/stage-probe-short-circuit-readiness.yml"
  awk '
    /^          \[\[ "\$rootless_userns" == true \]\]$/ && !mutated {
      print "          false && { :"
      print $0
      in_assertions=1
      mutated=1
      next
    }
    in_assertions && index($0, "assert_active_runner_binding \"${runner_units[0]}\" /proc/self/cgroup") {
      print $0
      print "          :; }"
      in_assertions=0
      next
    }
    {print}
  ' "$WORKFLOW" >"$short_circuit_readiness_stage_probe"
  short_circuit_readiness_script="$(sed -n '/^      - name: Read-only readiness verdict$/,$p' \
    "$short_circuit_readiness_stage_probe")"
  bash -n -s <<<"$(extract_stage_readiness_script "$short_circuit_readiness_script")" ||
    fail "short-circuit readiness fixture is not valid Bash"
  run_stage_probe_fixture "$short_circuit_readiness_stage_probe" \
    'FAIL  group-scoped stage probe readiness script differs from the reviewed executable contract' \
    "short-circuit readiness"
  printf 'PASS  short-circuit readiness assertions are rejected for the intended reason\n'

  decoy_readiness_stage_probe="$fixture_root/stage-probe-decoy-readiness.yml"
  awk '
    /^  stage-readiness:$/ {print "  decoy: {if: false}"}
    !mutated && $0 == "          [[ \"$rootless_userns\" == true ]]" {
      print "          false && { :"
      print
      in_assertions=1
      mutated=1
      next
    }
    in_assertions && index($0, "assert_active_runner_binding \"${runner_units[0]}\" /proc/self/cgroup") {
      print
      print "          :; }"
      in_assertions=0
      next
    }
    {print}
  ' "$WORKFLOW" >"$decoy_readiness_stage_probe"
  decoy_probe_block="$(awk '
    /^  stage-readiness:$/ {in_probe=1}
    in_probe && $0 != "  stage-readiness:" && /^  [a-zA-Z0-9_-]+:$/ {exit}
    in_probe {print}
  ' "$decoy_readiness_stage_probe")"
  decoy_readiness_script="$(sed -n '/^      - name: Read-only readiness verdict$/,$p' \
    <<<"$decoy_probe_block")"
  bash -n -s <<<"$(extract_stage_readiness_script "$decoy_readiness_script")" ||
    fail "decoy readiness fixture real probe is not valid Bash"
  run_stage_probe_fixture "$decoy_readiness_stage_probe" \
    'FAIL  release workflow contains an unexpected or missing job' \
    "skipped decoy readiness"
  printf 'PASS  skipped decoy cannot authenticate inert real-probe readiness\n'

  unbound_runner_stage_probe="$fixture_root/stage-probe-unbound-runner.yml"
  sed '/assert_active_runner_binding "${runner_units\[0\]}" \/proc\/self\/cgroup/d' \
    "$WORKFLOW" >"$unbound_runner_stage_probe"
  run_stage_probe_fixture "$unbound_runner_stage_probe" \
    'FAIL  group-scoped stage probe does not execute the active runner/cgroup binding directly' \
    "unbound runner service"
  printf 'PASS  unbound runner service is rejected for the intended reason\n'

  user_scope_runner_stage_probe="$fixture_root/stage-probe-user-scope-runner.yml"
  sed 's#assert_active_runner_binding "${runner_units\[0\]}" /proc/self/cgroup#assert_active_runner_binding "${runner_units[0]}" /proc/self/cgroup-user#' \
    "$WORKFLOW" >"$user_scope_runner_stage_probe"
  run_stage_probe_fixture "$user_scope_runner_stage_probe" \
    'FAIL  group-scoped stage probe does not execute the active runner/cgroup binding directly' \
    "user-scope runner cgroup"
  printf 'PASS  user-scope runner cgroup is rejected for the intended reason\n'

  broad_installed_runner_stage_probe="$fixture_root/stage-probe-broad-installed-runner.yml"
  sed 's/\[\[ "${#installed_runner_units\[@\]}" -eq 1 \]\]/[[ "${#installed_runner_units[@]}" -ge 1 ]]/' \
    "$WORKFLOW" >"$broad_installed_runner_stage_probe"
  run_stage_probe_fixture "$broad_installed_runner_stage_probe" \
    'FAIL  group-scoped stage probe does not execute the single installed runner-unit requirement directly' \
    "broad installed runner inventory"
  printf 'PASS  broad installed runner inventory is rejected for the intended reason\n'

  body_capture_health_stage_probe="$fixture_root/stage-probe-body-capture-health.yml"
  sed 's#^          curl --fail --silent --show-error --max-time 10 -o /dev/null http://127.0.0.1:9446/health$#          health_body="$(curl --fail --silent --show-error --max-time 10 http://127.0.0.1:9446/health)"#' \
    "$WORKFLOW" >"$body_capture_health_stage_probe"
  run_stage_probe_fixture "$body_capture_health_stage_probe" \
    'FAIL  group-scoped stage probe does not execute the body-suppressing health verdict directly' \
    "health body capture"
  printf 'PASS  health body capture is rejected for the intended reason\n'

  degraded_health_stage_probe="$fixture_root/stage-probe-degraded-health.yml"
  sed 's#curl --fail --silent --show-error --max-time 10 -o /dev/null#curl --silent --show-error --max-time 10 -o /dev/null#' \
    "$WORKFLOW" >"$degraded_health_stage_probe"
  run_stage_probe_fixture "$degraded_health_stage_probe" \
    'FAIL  group-scoped stage probe does not execute the body-suppressing health verdict directly' \
    "degraded health acceptance"
  printf 'PASS  degraded health acceptance is rejected for the intended reason\n'

  mutating_stage_probe="$fixture_root/stage-probe-systemd-mutation.yml"
  sed '/rootless_userns=/a\          systemctl restart disk-arcana-server' \
    "$WORKFLOW" >"$mutating_stage_probe"
  run_stage_probe_fixture "$mutating_stage_probe" \
    'FAIL  group-scoped stage probe contains a host mutation' \
    "stage systemd mutation"
  printf 'PASS  stage systemd mutation is rejected for the intended reason\n'

  writing_stage_probe="$fixture_root/stage-probe-host-write.yml"
  sed '/rootless_userns=/a\          printf mutated >disk-arcana-stage-probe-mutant' \
    "$WORKFLOW" >"$writing_stage_probe"
  run_stage_probe_fixture "$writing_stage_probe" \
    'FAIL  group-scoped stage probe writes to a host path' \
    "stage host write"
  printf 'PASS  stage host write is rejected for the intended reason\n'

  read_write_stage_probe="$fixture_root/stage-probe-read-write.yml"
  sed '/rootless_userns=/a\          exec 3<>disk-arcana-stage-probe-mutant' \
    "$WORKFLOW" >"$read_write_stage_probe"
  run_stage_probe_fixture "$read_write_stage_probe" \
    'FAIL  group-scoped stage probe writes to a host path' \
    "stage read-write redirection"
  printf 'PASS  stage read-write redirection is rejected for the intended reason\n'

  offhost_curl_stage_probe="$fixture_root/stage-probe-offhost-curl.yml"
  sed '/^          printf '\''readiness=ok/i\          curl --fail --silent https://example.com/' \
    "$WORKFLOW" >"$offhost_curl_stage_probe"
  run_stage_probe_fixture "$offhost_curl_stage_probe" \
    'FAIL  group-scoped stage probe contains an additional network request' \
    "off-host stage probe request"
  printf 'PASS  off-host stage probe request is rejected for the intended reason\n'

  docker_accept_stage_probe="$fixture_root/stage-probe-docker-accept.yml"
  sed 's/\[\[ "$docker_socket_writable" == false \]\]/[[ "$docker_socket_writable" == true ]]/' \
    "$WORKFLOW" >"$docker_accept_stage_probe"
  run_stage_probe_fixture "$docker_accept_stage_probe" \
    'FAIL  group-scoped stage probe does not execute the writable-Docker rejection directly' \
    "writable Docker acceptance"
  printf 'PASS  writable Docker acceptance is rejected for the intended reason\n'

  root_accept_stage_probe="$fixture_root/stage-probe-root-accept.yml"
  sed 's/\[\[ "$(id -u)" != 0 \]\]/[[ "$(id -u)" == 0 ]]/' \
    "$WORKFLOW" >"$root_accept_stage_probe"
  run_stage_probe_fixture "$root_accept_stage_probe" \
    'FAIL  group-scoped stage probe does not execute the non-root rejection directly' \
    "root UID acceptance"
  printf 'PASS  root UID acceptance is rejected for the intended reason\n'

  broad_sudo_stage_probe="$fixture_root/stage-probe-broad-sudo.yml"
  sed "s#\[\[ \"\${sudo_specs\[0\]}\" == '(root) NOPASSWD: /usr/local/sbin/disk-arcana-deploy-broker --deploy \*' \]\]#[[ \"\${sudo_specs[0]}\" == *disk-arcana-deploy-broker* ]]#" \
    "$WORKFLOW" >"$broad_sudo_stage_probe"
  run_stage_probe_fixture "$broad_sudo_stage_probe" \
    'FAIL  group-scoped stage probe lacks the exact narrow sudo command specification' \
    "broad sudo acceptance"
  printf 'PASS  broad sudo acceptance is rejected for the intended reason\n'
fi

printf 'PASS  release workflow deploys one manifest-bound artifact through staging then production\n'
