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

count_exact_command() {
  local file="$1" expected="$2"
  awk -v expected="$expected" '
    {line=$0; sub(/^[[:space:]]+/, "", line); sub(/[[:space:]]+$/, "", line)}
    line == expected {count++}
    END {print count + 0}
  ' "$file"
}

assert_stage_top_level_command() {
  local block="$1" expected="$2" label="$3"
  grep -qxF "          $expected" <<<"$block" ||
    fail "$label is not an unconditional top-level command"
}

[[ -f "$STAGE_PROBE_WORKFLOW" ]] || fail "stage runner probe workflow is missing"

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
isolation_step="$(sed -n '/^      - name: Staging isolation capabilities$/,/^      - name: systemd version$/p' "$PROBE_WORKFLOW")"
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

stage_probe_trigger="$(sed -n '/^on:$/,/^permissions:/p' "$STAGE_PROBE_WORKFLOW")"
stage_probe_job="$(sed -n '/^  readiness:/,$p' "$STAGE_PROBE_WORKFLOW")"
stage_source_step="$(sed -n '/^      - name: Require exact main source$/,/^      - name: Read-only staging readiness$/p' "$STAGE_PROBE_WORKFLOW")"
stage_readiness_step="$(sed -n '/^      - name: Read-only staging readiness$/,$p' "$STAGE_PROBE_WORKFLOW")"

grep -qxF 'name: Stage runner probe (read-only)' "$STAGE_PROBE_WORKFLOW" ||
  fail "stage runner probe workflow name is not exact"
[[ "$stage_probe_trigger" == $'on:\n  workflow_dispatch:\npermissions: {}' ]] ||
  fail "stage runner probe trigger or permissions are not minimal"
[[ "$(grep -oE '(^|[,{[:space:]-])permissions[[:space:]]*:' "$STAGE_PROBE_WORKFLOW" | wc -l)" -eq 1 ]] ||
  fail "stage runner probe overrides the empty permissions envelope"
grep -qE '^      group:' "$STAGE_PROBE_WORKFLOW" ||
  fail "stage runner probe is missing its runner group"
grep -qF '      group: disk-arcana-stage' "$STAGE_PROBE_WORKFLOW" ||
  fail "stage runner probe uses the wrong runner group"
grep -qF '      labels: [self-hosted, Linux, X64, disk-arcana-stage]' "$STAGE_PROBE_WORKFLOW" ||
  fail "stage runner probe does not require all dedicated runner labels"
[[ "$stage_probe_job" == *'name: Dedicated staging runner readiness'* ]] ||
  fail "stage runner probe job name is not exact"
[[ "$stage_probe_job" == *'environment: staging'* ]] ||
  fail "stage runner probe does not use the staging environment"
! grep -qE '(^|[,{[:space:]-])uses[[:space:]]*:' "$STAGE_PROBE_WORKFLOW" ||
  fail "stage runner probe must not use actions"
[[ "$(grep -cE '^      - name:' "$STAGE_PROBE_WORKFLOW")" -eq 2 ]] ||
  fail "stage runner probe must contain exactly two named steps"
[[ "$(grep -cF '        run:' "$STAGE_PROBE_WORKFLOW")" -eq 2 ]] ||
  fail "stage runner probe must contain exactly two executable steps"

[[ "$stage_source_step" == *'run: |'* ]] ||
  fail "stage runner source guard is not an executable shell step"
! grep -qE '^        (if|continue-on-error):' <<<"$stage_source_step" ||
  fail "stage runner source guard is conditional or non-blocking"
expected_source_guard=$'        run: |\n          set -euo pipefail\n          [[ "$GITHUB_REF" == "refs/heads/main" ]]\n          [[ "$GITHUB_REPOSITORY" == "Arcanada-one/disk-arcana" ]]\n          [[ "$GITHUB_WORKFLOW_REF" == "Arcanada-one/disk-arcana/.github/workflows/stage-runner-probe.yml@refs/heads/main" ]]'
[[ "$stage_source_step" == *"$expected_source_guard"* ]] ||
  fail "stage runner source guard is not unconditional and exact"

[[ "$stage_readiness_step" == *'run: |'* ]] ||
  fail "stage runner readiness probe is not executable"
! grep -qE '^        (if|continue-on-error):' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe is conditional or non-blocking"
! grep -qE '^          set[[:space:]]+\+([euo]|o[[:space:]]+pipefail)([[:space:]]|$)' \
    <<<"$stage_readiness_step" || fail "stage runner readiness probe disables fail-closed execution"
! grep -qE '^          (if|for|while|until|case|select)([[:space:]]|$)|^          [^[:space:]].*(&&|\|\|)' \
    <<<"$stage_readiness_step" || fail "stage runner readiness predicates are conditionally sequenced"
grep -qF '[[ "$runner_uid" != 0 ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not reject root UID"
grep -qF 'rootless_userns="$(bool_command unshare --user --map-root-user true)"' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not execute the rootless-userns predicate"
grep -qF '[[ "$rootless_userns" == true ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require rootless user namespaces"
grep -qF 'subuid_count="$(subid_count /etc/subuid)"' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not count subordinate UIDs"
grep -qF 'subgid_count="$(subid_count /etc/subgid)"' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not count subordinate GIDs"
grep -qF '(( subuid_count >= 65536 ))' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require 65536 subordinate UIDs"
grep -qF '(( subgid_count >= 65536 ))' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require 65536 subordinate GIDs"
grep -qF 'user_systemd="$(bool_command systemctl --user show-environment)"' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not execute the user-systemd predicate"
grep -qF '[[ "$user_systemd" == true ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require user systemd"
grep -qF 'linger="$(loginctl show-user "$runner_uid" -p Linger --value 2>/dev/null)"' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not read exact linger state"
grep -qF '[[ "$linger" == yes ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require linger"
grep -qF 'podman="$(bool_command command -v podman)"' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not execute the Podman predicate"
grep -qF '[[ "$podman" == true ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require Podman"
grep -qF 'docker_socket_writable="$(bool_command test -w /var/run/docker.sock)"' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not inspect Docker socket writability"
grep -qF '[[ "$docker_socket_writable" == false ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not reject writable Docker"
grep -qF '[[ "$runner_services" -eq 1 ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require exactly one runner service"
grep -qF "systemctl list-units --type=service --all 'actions.runner.*'" <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not count runner services"
grep -qF 'grep -qxF disk-arcana-deploy' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require the deploy group"
if [[ "$(grep -cF 'sudo -n -l 2>/dev/null' <<<"$stage_readiness_step")" -ne 1 ]] ||
    ! grep -qxF "            sudo -n -l 2>/dev/null | awk '" <<<"$stage_readiness_step"; then
  fail "stage runner readiness probe does not reduce one sudo listing"
fi
[[ "$(grep -oE '(^|[;&|({[:space:]-])sudo[[:space:]]+' <<<"$stage_readiness_step" | wc -l)" -eq 1 ]] ||
  fail "stage runner readiness probe exposes a raw or extra sudo listing"
grep -qF '[[ "$sudo_command_count" -eq 1 ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require one sudo command"
grep -qF '/NOPASSWD:/ {' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not reduce NOPASSWD commands"
grep -qF '[[ "$sudo_command" == '\''/usr/local/sbin/disk-arcana-deploy-broker --deploy *'\'' ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe broadens the exact sudo command"
grep -qF 'unit=/etc/systemd/system/disk-arcana-server.service' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not name the service unit"
grep -qF '[[ -f "$unit" ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require the unit file"
grep -qF 'systemctl is-active --quiet disk-arcana-server' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require the active unit"
grep -qF '[[ "$(systemctl is-enabled disk-arcana-server)" == enabled ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require the enabled unit"
grep -qF 'restart="$(systemctl show disk-arcana-server -p Restart --value)"' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not read Restart"
grep -qF 'start_limit_interval="$(systemctl show disk-arcana-server -p StartLimitIntervalUSec --value)"' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not read StartLimitIntervalUSec"
grep -qF 'start_limit_burst="$(systemctl show disk-arcana-server -p StartLimitBurst --value)"' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not read StartLimitBurst"
grep -qF '[[ "$restart" == on-failure ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require Restart=on-failure"
grep -qF '[[ "$start_limit_interval" == 2min ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require StartLimitIntervalUSec=2min"
grep -qF '[[ "$start_limit_burst" == 5 ]]' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not require StartLimitBurst=5"
grep -qF "curl --fail --silent --show-error --max-time 10 -o /dev/null \\" <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not discard the health body"
grep -qF 'http://127.0.0.1:9446/health' <<<"$stage_readiness_step" ||
  fail "stage runner readiness probe does not check the service health endpoint"
! grep -qE 'printf[^\n]*(sudo_summary|sudo_command)|echo[^\n]*(sudo_summary|sudo_command)' \
    <<<"$stage_readiness_step" || fail "stage runner readiness probe prints sudo details"

readiness_marker="printf 'stage_runner_readiness=ok runner_services=%s\\n' \"\$runner_services\""
[[ "$(grep -cFx "          $readiness_marker" <<<"$stage_readiness_step")" -eq 1 ]] ||
  fail "stage runner readiness probe does not have one exact final marker"
readiness_marker_line="$(grep -nFx "          $readiness_marker" <<<"$stage_readiness_step" | cut -d: -f1)"
stage_before_readiness_marker="$(sed -n "1,$((readiness_marker_line - 1))p" <<<"$stage_readiness_step")"
stage_after_readiness_marker="$(sed -n "$((readiness_marker_line + 1)),\$p" <<<"$stage_readiness_step")"
[[ -z "$stage_after_readiness_marker" ]] ||
  fail "stage runner readiness marker is not the final command"
! grep -qE '(^|[;&|({[:space:]-])(exit|return)([[:space:];)}]|$)' \
    <<<"$stage_before_readiness_marker" ||
  fail "stage runner readiness probe terminates successfully before its final marker"

assert_stage_top_level_command "$stage_readiness_step" '[[ "$runner_uid" != 0 ]]' "root UID predicate"
assert_stage_top_level_command "$stage_readiness_step" '[[ "$rootless_userns" == true ]]' "rootless-userns predicate"
assert_stage_top_level_command "$stage_readiness_step" '(( subuid_count >= 65536 ))' "subordinate-UID predicate"
assert_stage_top_level_command "$stage_readiness_step" '(( subgid_count >= 65536 ))' "subordinate-GID predicate"
assert_stage_top_level_command "$stage_readiness_step" '[[ "$user_systemd" == true ]]' "user-systemd predicate"
assert_stage_top_level_command "$stage_readiness_step" '[[ "$linger" == yes ]]' "linger predicate"
assert_stage_top_level_command "$stage_readiness_step" '[[ "$podman" == true ]]' "Podman predicate"
assert_stage_top_level_command "$stage_readiness_step" '[[ "$docker_socket_writable" == false ]]' "Docker-socket predicate"
assert_stage_top_level_command "$stage_readiness_step" '[[ "$runner_services" -eq 1 ]]' "runner-service predicate"
assert_stage_top_level_command "$stage_readiness_step" "id -nG \"\$runner_user\" | tr ' ' '\\n' | grep -qxF disk-arcana-deploy" "deploy-group predicate"
assert_stage_top_level_command "$stage_readiness_step" '[[ "$sudo_command_count" -eq 1 ]]' "sudo-count predicate"
assert_stage_top_level_command "$stage_readiness_step" '[[ "$sudo_command" == '\''/usr/local/sbin/disk-arcana-deploy-broker --deploy *'\'' ]]' "sudo-command predicate"
assert_stage_top_level_command "$stage_readiness_step" '[[ -f "$unit" ]]' "unit-file predicate"
assert_stage_top_level_command "$stage_readiness_step" 'systemctl is-active --quiet disk-arcana-server' "active-unit predicate"
assert_stage_top_level_command "$stage_readiness_step" '[[ "$(systemctl is-enabled disk-arcana-server)" == enabled ]]' "enabled-unit predicate"
assert_stage_top_level_command "$stage_readiness_step" '[[ "$restart" == on-failure ]]' "restart-policy predicate"
assert_stage_top_level_command "$stage_readiness_step" '[[ "$start_limit_interval" == 2min ]]' "start-limit-interval predicate"
assert_stage_top_level_command "$stage_readiness_step" '[[ "$start_limit_burst" == 5 ]]' "start-limit-burst predicate"
assert_stage_top_level_command "$stage_readiness_step" "curl --fail --silent --show-error --max-time 10 -o /dev/null \\" "health predicate"
assert_stage_top_level_command "$stage_readiness_step" "$readiness_marker" "readiness marker"

if grep -oE '(^|[[:space:]])of=[^[:space:]]+' <<<"$stage_readiness_step" |
    grep -qvE '(^|[[:space:]])of=/dev/null$'; then
  fail "stage runner readiness probe contains a host write"
fi
! grep -qE '(^|[;&|])[[:space:]]*(rm|mv|cp|install|touch|mkdir|chmod|chown|setfacl|tee|truncate|mount|umount|kill|pkill|reboot|shutdown|apt|apt-get|dnf|yum|pacman|snap)[[:space:]]|systemctl[[:space:]]+(--user[[:space:]]+)?(enable|disable|start|stop|restart|reload|daemon-reload|mask|unmask|edit|link|preset)|loginctl[[:space:]]+(enable-linger|disable-linger)|(^|[;&|])[[:space:]]*(podman|docker)[[:space:]]+(run|create|start|stop|restart|rm|build|pull|push|exec)' \
    <<<"$stage_readiness_step" || fail "stage runner readiness probe contains a mutation"
stage_redirect_scan="$(sed -E \
  -e 's#2?>/dev/null([[:space:];|&)]|$)#\1#g' \
  -e 's#2>&1([[:space:];|&)]|$)#\1#g' \
  <<<"$stage_readiness_step")"
! grep -qE '<>|(^|[^<])>{1,2}([^=]|$)' <<<"$stage_redirect_scan" ||
  fail "stage runner readiness probe writes outside /dev/null"
! grep -qE '(^|[[:space:]])(env|printenv|export[[:space:]]+-p)([[:space:]]|$)|/proc/[^[:space:]]*/environ' \
    <<<"$stage_readiness_step" || fail "stage runner readiness probe dumps environment data"
! grep -qE '/etc/(shadow|gshadow|sudoers)([^[:alnum:]_.-]|$)|config/credentials|\.ssh/' \
    <<<"$stage_readiness_step" || fail "stage runner readiness probe reads a protected path"

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

  run_release_fixture() {
    local workflow="$1" expected="$2" label="$3" fixture_rc
    set +e
    DISK_ARCANA_ORDER_FIXTURE_CHILD=1 \
      WORKFLOW_OVERRIDE="$workflow" \
      SHARE_WORKFLOW_OVERRIDE="$SHARE_WORKFLOW" \
      PROBE_WORKFLOW_OVERRIDE="$PROBE_WORKFLOW" \
      STAGE_PROBE_WORKFLOW_OVERRIDE="$STAGE_PROBE_WORKFLOW" \
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
      STAGE_PROBE_WORKFLOW_OVERRIDE="$STAGE_PROBE_WORKFLOW" \
      "$0" >"$fixture_output" 2>&1
    fixture_rc=$?
    set -e
    [[ "$fixture_rc" -ne 0 ]] || fail "$label fixture passed"
    grep -qF "$expected" "$fixture_output" || fail "$label fixture failed for an unintended reason"
  }

  run_stage_probe_fixture() {
    local probe="$1" expected="$2" label="$3" fixture_rc
    set +e
    DISK_ARCANA_ORDER_FIXTURE_CHILD=1 \
      WORKFLOW_OVERRIDE="$WORKFLOW" \
      SHARE_WORKFLOW_OVERRIDE="$SHARE_WORKFLOW" \
      PROBE_WORKFLOW_OVERRIDE="$PROBE_WORKFLOW" \
      STAGE_PROBE_WORKFLOW_OVERRIDE="$probe" \
      "$0" >"$fixture_output" 2>&1
    fixture_rc=$?
    set -e
    [[ "$fixture_rc" -ne 0 ]] || fail "$label fixture passed"
    grep -qF "$expected" "$fixture_output" || fail "$label fixture failed for an unintended reason"
  }

  review_gap_failures=0
  run_stage_review_fixture() {
    local probe="$1" expected="$2" label="$3" fixture_rc
    set +e
    DISK_ARCANA_ORDER_FIXTURE_CHILD=1 \
      WORKFLOW_OVERRIDE="$WORKFLOW" \
      SHARE_WORKFLOW_OVERRIDE="$SHARE_WORKFLOW" \
      PROBE_WORKFLOW_OVERRIDE="$PROBE_WORKFLOW" \
      STAGE_PROBE_WORKFLOW_OVERRIDE="$probe" \
      "$0" >"$fixture_output" 2>&1
    fixture_rc=$?
    set -e
    if [[ "$fixture_rc" -eq 0 ]]; then
      printf 'RED   %s mutant was accepted by the current contract\n' "$label"
      ((review_gap_failures += 1))
      return
    fi
    grep -qF "$expected" "$fixture_output" || fail "$label fixture failed for an unintended reason"
    printf 'PASS  %s mutant is rejected for the intended reason\n' "$label"
  }

  stage_group_removed="$fixture_root/stage-probe-group-removed.yml"
  sed '/^      group: disk-arcana-stage$/d' "$STAGE_PROBE_WORKFLOW" >"$stage_group_removed"
  run_stage_probe_fixture "$stage_group_removed" \
    'FAIL  stage runner probe is missing its runner group' \
    "removed stage runner group"
  printf 'PASS  removed stage runner group is rejected while labels remain\n'

  stage_group_wrong="$fixture_root/stage-probe-group-wrong.yml"
  sed 's/^      group: disk-arcana-stage$/      group: disk-arcana-other/' \
    "$STAGE_PROBE_WORKFLOW" >"$stage_group_wrong"
  run_stage_probe_fixture "$stage_group_wrong" \
    'FAIL  stage runner probe uses the wrong runner group' \
    "wrong stage runner group"
  printf 'PASS  wrong stage runner group is rejected for the intended reason\n'

  stage_uses="$fixture_root/stage-probe-uses.yml"
  sed '/^    steps:$/a\      - uses: actions/checkout@0000000000000000000000000000000000000000' \
    "$STAGE_PROBE_WORKFLOW" >"$stage_uses"
  run_stage_probe_fixture "$stage_uses" \
    'FAIL  stage runner probe must not use actions' \
    "checkout uses step"
  printf 'PASS  checkout uses step is rejected for the intended reason\n'

  stage_guard_disabled="$fixture_root/stage-probe-disabled-source-guard.yml"
  awk '
    /^          \[\[ "\$GITHUB_REF" == "refs\/heads\/main" \]\]$/ {
      print "          if false; then"
      print "  " $0
      in_guard=1
      next
    }
    in_guard && /GITHUB_WORKFLOW_REF/ {
      print "  " $0
      print "          fi"
      in_guard=0
      next
    }
    {print}
  ' "$STAGE_PROBE_WORKFLOW" >"$stage_guard_disabled"
  run_stage_probe_fixture "$stage_guard_disabled" \
    'FAIL  stage runner source guard is not unconditional and exact' \
    "disabled stage source guard"
  printf 'PASS  if-false stage source guard is rejected as non-load-bearing\n'

  stage_systemctl_restart="$fixture_root/stage-probe-systemctl-restart.yml"
  sed '/\[\[ "$runner_uid" != 0 \]\]/a\          systemctl restart disk-arcana-server' \
    "$STAGE_PROBE_WORKFLOW" >"$stage_systemctl_restart"
  run_stage_probe_fixture "$stage_systemctl_restart" \
    'FAIL  stage runner readiness probe contains a mutation' \
    "stage systemctl restart"
  printf 'PASS  stage systemctl restart is rejected for the intended reason\n'

  stage_host_write="$fixture_root/stage-probe-host-write.yml"
  sed '/\[\[ "$runner_uid" != 0 \]\]/a\          printf mutated >stage-runner-probe-mutant' \
    "$STAGE_PROBE_WORKFLOW" >"$stage_host_write"
  run_stage_probe_fixture "$stage_host_write" \
    'FAIL  stage runner readiness probe writes outside /dev/null' \
    "stage host write"
  printf 'PASS  stage host write is rejected for the intended reason\n'

  stage_read_write="$fixture_root/stage-probe-read-write.yml"
  sed '/\[\[ "$runner_uid" != 0 \]\]/a\          exec 3<>stage-runner-probe-mutant' \
    "$STAGE_PROBE_WORKFLOW" >"$stage_read_write"
  run_stage_probe_fixture "$stage_read_write" \
    'FAIL  stage runner readiness probe writes outside /dev/null' \
    "stage read-write redirection"
  printf 'PASS  stage read-write redirection is rejected for the intended reason\n'

  stage_docker_inverted="$fixture_root/stage-probe-docker-inverted.yml"
  sed 's/\[\[ "$docker_socket_writable" == false \]\]/[[ "$docker_socket_writable" == true ]]/' \
    "$STAGE_PROBE_WORKFLOW" >"$stage_docker_inverted"
  run_stage_probe_fixture "$stage_docker_inverted" \
    'FAIL  stage runner readiness probe does not reject writable Docker' \
    "inverted writable-Docker acceptance"
  printf 'PASS  inverted writable-Docker acceptance is rejected for the intended reason\n'

  stage_uid_inverted="$fixture_root/stage-probe-uid-inverted.yml"
  sed 's/\[\[ "$runner_uid" != 0 \]\]/[[ "$runner_uid" == 0 ]]/' \
    "$STAGE_PROBE_WORKFLOW" >"$stage_uid_inverted"
  run_stage_probe_fixture "$stage_uid_inverted" \
    'FAIL  stage runner readiness probe does not reject root UID' \
    "inverted root-UID acceptance"
  printf 'PASS  inverted root-UID acceptance is rejected for the intended reason\n'

  stage_sudo_broadened="$fixture_root/stage-probe-sudo-broadened.yml"
  sed 's#\[\[ "$sudo_command" == '\''/usr/local/sbin/disk-arcana-deploy-broker --deploy \*'\'' \]\]#[[ "$sudo_command" == /usr/local/sbin/disk-arcana-deploy-broker* ]]#' \
    "$STAGE_PROBE_WORKFLOW" >"$stage_sudo_broadened"
  run_stage_probe_fixture "$stage_sudo_broadened" \
    'FAIL  stage runner readiness probe broadens the exact sudo command' \
    "broadened sudo comparison"
  printf 'PASS  broadened sudo comparison is rejected for the intended reason\n'

  stage_disable_errexit="$fixture_root/stage-probe-disable-errexit.yml"
  awk '
    /^      - name: Read-only staging readiness$/ {in_readiness=1}
    in_readiness && !mutated && /^          set -euo pipefail$/ {
      print
      print "          set +e"
      mutated=1
      next
    }
    {print}
  ' "$STAGE_PROBE_WORKFLOW" >"$stage_disable_errexit"
  run_stage_review_fixture "$stage_disable_errexit" \
    'FAIL  stage runner readiness probe disables fail-closed execution' \
    "disabled readiness errexit"

  stage_job_permissions="$fixture_root/stage-probe-job-permissions.yml"
  sed '/^    environment: staging$/a\    permissions: write-all' \
    "$STAGE_PROBE_WORKFLOW" >"$stage_job_permissions"
  run_stage_review_fixture "$stage_job_permissions" \
    'FAIL  stage runner probe overrides the empty permissions envelope' \
    "job-level permissions override"

  stage_inline_uses="$fixture_root/stage-probe-inline-uses.yml"
  sed '/^    steps:$/a\      - {uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1}' \
    "$STAGE_PROBE_WORKFLOW" >"$stage_inline_uses"
  run_stage_review_fixture "$stage_inline_uses" \
    'FAIL  stage runner probe must not use actions' \
    "inline checkout uses"

  stage_dd_write="$fixture_root/stage-probe-dd-write.yml"
  sed '/\[\[ "$runner_uid" != 0 \]\]/a\          dd if=/dev/zero of=/tmp/stage-runner-probe-mutant status=none' \
    "$STAGE_PROBE_WORKFLOW" >"$stage_dd_write"
  run_stage_review_fixture "$stage_dd_write" \
    'FAIL  stage runner readiness probe contains a host write' \
    "dd of host write"

  stage_extra_sudo="$fixture_root/stage-probe-extra-sudo.yml"
  sed '/\[\[ "$runner_uid" != 0 \]\]/a\          sudo -n -l' \
    "$STAGE_PROBE_WORKFLOW" >"$stage_extra_sudo"
  run_stage_review_fixture "$stage_extra_sudo" \
    'FAIL  stage runner readiness probe exposes a raw or extra sudo listing' \
    "extra raw sudo listing"

  stage_early_exit="$fixture_root/stage-probe-early-exit.yml"
  awk '
    /^      - name: Read-only staging readiness$/ {in_readiness=1}
    in_readiness && !mutated && /^          set -euo pipefail$/ {
      print
      print "          exit 0"
      mutated=1
      next
    }
    {print}
  ' "$STAGE_PROBE_WORKFLOW" >"$stage_early_exit"
  run_stage_review_fixture "$stage_early_exit" \
    'FAIL  stage runner readiness probe terminates successfully before its final marker' \
    "early successful exit"

  stage_early_return="$fixture_root/stage-probe-early-return.yml"
  awk '
    /^      - name: Read-only staging readiness$/ {in_readiness=1}
    in_readiness && !mutated && /^          set -euo pipefail$/ {
      print
      print "          return 0"
      mutated=1
      next
    }
    {print}
  ' "$STAGE_PROBE_WORKFLOW" >"$stage_early_return"
  run_stage_review_fixture "$stage_early_return" \
    'FAIL  stage runner readiness probe terminates successfully before its final marker' \
    "early successful return"

  (( review_gap_failures == 0 )) ||
    fail "$review_gap_failures stage runner review-gap mutants were accepted"

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
fi

printf 'PASS  release workflow deploys one manifest-bound artifact through staging then production\n'
