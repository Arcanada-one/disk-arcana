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
[[ -f "$STAGE_PROBE_WORKFLOW" ]] || fail "group-scoped stage probe workflow is absent"
stage_probe_block="$(sed -n '/^  probe:/,$p' "$STAGE_PROBE_WORKFLOW")"
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

grep -qF 'name: Stage runner probe (read-only)' "$STAGE_PROBE_WORKFLOW" ||
  fail "group-scoped stage probe has the wrong workflow identity"
stage_probe_on="$(sed -n '/^on:/,/^permissions:/p' "$STAGE_PROBE_WORKFLOW")"
[[ "$stage_probe_on" == *'workflow_dispatch:'* ]] ||
  fail "group-scoped stage probe is not workflow-dispatch enabled"
stage_probe_trigger_count="$(awk '
  /^on:$/ {in_on=1; next}
  /^permissions:/ {in_on=0}
  in_on && /^  [a-zA-Z0-9_-]+:$/ {count++}
  END {print count + 0}
' "$STAGE_PROBE_WORKFLOW")"
[[ "$stage_probe_trigger_count" == 1 ]] ||
  fail "group-scoped stage probe has an additional trigger"
grep -qF 'permissions: {}' "$STAGE_PROBE_WORKFLOW" ||
  fail "group-scoped stage probe permissions are not empty"
grep -qF 'group: disk-arcana-stage' <<<"$stage_probe_block" ||
  fail "group-scoped stage probe does not require runner group disk-arcana-stage"
grep -qF 'labels: [self-hosted, Linux, X64, disk-arcana-stage]' <<<"$stage_probe_block" ||
  fail "group-scoped stage probe does not require the exact dedicated labels"
grep -qF 'environment: staging' <<<"$stage_probe_block" ||
  fail "group-scoped stage probe does not use the staging environment"
! grep -qE '^[[:space:]]*-[[:space:]]*uses:' "$STAGE_PROBE_WORKFLOW" ||
  fail "group-scoped stage probe is not actionless"
! grep -qE '^[[:space:]]*(if|continue-on-error):' <<<"$stage_probe_block" ||
  fail "group-scoped stage probe contains a skippable or non-blocking step"

stage_source_guard="$(sed -n '/^      - name: Exact main source$/,/^      - name: Read-only readiness verdict$/p' \
  "$STAGE_PROBE_WORKFLOW")"
! grep -qE '^[[:space:]]*(if|then|elif|else|case|while|until|for)[[:space:]]' \
  <<<"$stage_source_guard" ||
  fail "group-scoped stage probe exact-main guard is conditional"
grep -qFx '          [[ "$GITHUB_REF" == refs/heads/main ]]' <<<"$stage_source_guard" ||
  fail "group-scoped stage probe does not execute the exact-main guard directly"
grep -qFx '          [[ "$GITHUB_REPOSITORY" == Arcanada-one/disk-arcana ]]' \
  <<<"$stage_source_guard" ||
  fail "group-scoped stage probe does not execute the repository guard directly"
grep -qFx '          [[ "$GITHUB_WORKFLOW_REF" == Arcanada-one/disk-arcana/.github/workflows/stage-runner-probe.yml@refs/heads/main ]]' \
  <<<"$stage_source_guard" ||
  fail "group-scoped stage probe does not execute its exact workflow-reference guard directly"

[[ "$stage_probe_block" == *'[[ "$(id -u)" != 0 ]]'* ]] ||
  fail "group-scoped stage probe does not reject root execution"
[[ "$stage_probe_block" == *'[[ "$rootless_userns" == true ]]'* ]] ||
  fail "group-scoped stage probe does not require a rootless user namespace"
[[ "$stage_probe_block" == *'(( subuid_count >= 65536 ))'* ]] ||
  fail "group-scoped stage probe does not require subordinate UIDs"
[[ "$stage_probe_block" == *'(( subgid_count >= 65536 ))'* ]] ||
  fail "group-scoped stage probe does not require subordinate GIDs"
[[ "$stage_probe_block" == *'[[ "$user_systemd" == true ]]'* ]] ||
  fail "group-scoped stage probe does not require user systemd"
[[ "$stage_probe_block" == *'[[ "$linger" == yes ]]'* ]] ||
  fail "group-scoped stage probe does not require linger"
[[ "$stage_probe_block" == *'[[ "$podman" == true ]]'* ]] ||
  fail "group-scoped stage probe does not require podman"
[[ "$stage_probe_block" == *'[[ "$docker_socket_writable" == false ]]'* ]] ||
  fail "group-scoped stage probe does not reject writable Docker"
[[ "$stage_probe_block" == *'[[ "$runner_services" == 1 ]]'* ]] ||
  fail "group-scoped stage probe does not require exactly one runner service"
[[ "$stage_probe_block" == *'[[ " $(id -Gn) " == *" disk-arcana-deploy "* ]]'* ]] ||
  fail "group-scoped stage probe does not require the deployment group"
[[ "$stage_probe_block" == *'[[ "${#sudo_commands[@]}" -eq 1 ]]'* ]] ||
  fail "group-scoped stage probe does not require one sudo command"
[[ "$stage_probe_block" == *'[[ "${sudo_commands[0]}" == '\''/usr/local/sbin/disk-arcana-deploy-broker --deploy *'\'' ]]'* ]] ||
  fail "group-scoped stage probe does not require the exact narrow sudo command"
[[ "$stage_probe_block" == *'[[ -f /etc/systemd/system/disk-arcana-server.service ]]'* ]] ||
  fail "group-scoped stage probe does not require the installed unit"
[[ "$stage_probe_block" == *'[[ "$(systemctl is-active disk-arcana-server 2>/dev/null)" == active ]]'* ]] ||
  fail "group-scoped stage probe does not require the active service"
[[ "$stage_probe_block" == *'[[ "$(systemctl show disk-arcana-server -p UnitFileState --value 2>/dev/null)" == enabled ]]'* ]] ||
  fail "group-scoped stage probe does not require exact UnitFileState=enabled"
[[ "$stage_probe_block" == *'[[ "$(systemctl show disk-arcana-server -p Restart --value 2>/dev/null)" == on-failure ]]'* ]] ||
  fail "group-scoped stage probe does not require Restart=on-failure"
[[ "$stage_probe_block" == *'[[ "$(systemctl show disk-arcana-server -p StartLimitIntervalUSec --value 2>/dev/null)" == 2min ]]'* ]] ||
  fail "group-scoped stage probe does not require StartLimitIntervalUSec=2min"
[[ "$stage_probe_block" == *'[[ "$(systemctl show disk-arcana-server -p StartLimitBurst --value 2>/dev/null)" == 5 ]]'* ]] ||
  fail "group-scoped stage probe does not require StartLimitBurst=5"
[[ "$stage_probe_block" == *'curl --fail --silent --show-error --max-time 10 -o /dev/null'* ]] ||
  fail "group-scoped stage probe does not require a body-suppressed health check"
[[ "$(grep -cE '^[[:space:]]*curl[[:space:]]' <<<"$stage_probe_block")" -eq 1 ]] ||
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
  <<<"$stage_probe_block")"
! grep -qE '<>|(^|[^<])>{1,2}([^=]|$)' <<<"$stage_probe_redirect_scan" ||
  fail "group-scoped stage probe writes to a host path"
! grep -qE '(^|[[:space:]])(env|printenv|set)[[:space:]]*($|[|;&])|/etc/(shadow|sudoers|environment)|/proc/[0-9]+/environ' \
  <<<"$stage_probe_block" || fail "group-scoped stage probe reads protected process or credential state"

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
      WORKFLOW_OVERRIDE="$WORKFLOW" \
      SHARE_WORKFLOW_OVERRIDE="$SHARE_WORKFLOW" \
      PROBE_WORKFLOW_OVERRIDE="$PROBE_WORKFLOW" \
      STAGE_PROBE_WORKFLOW_OVERRIDE="$stage_probe" \
      "$0" >"$fixture_output" 2>&1
    fixture_rc=$?
    set -e
    [[ "$fixture_rc" -ne 0 ]] || fail "$label fixture passed"
    grep -qF "$expected" "$fixture_output" || fail "$label fixture failed for an unintended reason"
  }

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
  sed '/^[[:space:]]*group: disk-arcana-stage$/d' \
    "$STAGE_PROBE_WORKFLOW" >"$labels_only_stage_probe"
  run_stage_probe_fixture "$labels_only_stage_probe" \
    'FAIL  group-scoped stage probe does not require runner group disk-arcana-stage' \
    "labels-only stage probe"
  printf 'PASS  labels-only stage probe is rejected for the intended reason\n'

  wrong_group_stage_probe="$fixture_root/stage-probe-wrong-group.yml"
  sed 's/group: disk-arcana-stage/group: ci-general/' \
    "$STAGE_PROBE_WORKFLOW" >"$wrong_group_stage_probe"
  run_stage_probe_fixture "$wrong_group_stage_probe" \
    'FAIL  group-scoped stage probe does not require runner group disk-arcana-stage' \
    "wrong runner group"
  printf 'PASS  wrong runner group is rejected for the intended reason\n'

  action_stage_probe="$fixture_root/stage-probe-action.yml"
  sed '/^    steps:$/a\      - uses: actions/checkout@0000000000000000000000000000000000000000' \
    "$STAGE_PROBE_WORKFLOW" >"$action_stage_probe"
  run_stage_probe_fixture "$action_stage_probe" \
    'FAIL  group-scoped stage probe is not actionless' \
    "stage probe action step"
  printf 'PASS  added action step is rejected for the intended reason\n'

  extra_trigger_stage_probe="$fixture_root/stage-probe-extra-trigger.yml"
  sed '/^  workflow_dispatch:$/a\  repository_dispatch:' \
    "$STAGE_PROBE_WORKFLOW" >"$extra_trigger_stage_probe"
  run_stage_probe_fixture "$extra_trigger_stage_probe" \
    'FAIL  group-scoped stage probe has an additional trigger' \
    "additional stage probe trigger"
  printf 'PASS  additional stage probe trigger is rejected for the intended reason\n'

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
  ' "$STAGE_PROBE_WORKFLOW" >"$conditional_main_stage_probe"
  run_stage_probe_fixture "$conditional_main_stage_probe" \
    'FAIL  group-scoped stage probe exact-main guard is conditional' \
    "conditional exact-main guard"
  printf 'PASS  conditional exact-main guard is rejected for the intended reason\n'

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
  ' "$STAGE_PROBE_WORKFLOW" >"$inert_main_stage_probe"
  run_stage_probe_fixture "$inert_main_stage_probe" \
    'FAIL  group-scoped stage probe does not execute the exact-main guard directly' \
    "inert exact-main function"
  printf 'PASS  inert exact-main function is rejected for the intended reason\n'

  mutating_stage_probe="$fixture_root/stage-probe-systemd-mutation.yml"
  sed '/rootless_userns=/a\          systemctl restart disk-arcana-server' \
    "$STAGE_PROBE_WORKFLOW" >"$mutating_stage_probe"
  run_stage_probe_fixture "$mutating_stage_probe" \
    'FAIL  group-scoped stage probe contains a host mutation' \
    "stage systemd mutation"
  printf 'PASS  stage systemd mutation is rejected for the intended reason\n'

  writing_stage_probe="$fixture_root/stage-probe-host-write.yml"
  sed '/rootless_userns=/a\          printf mutated >disk-arcana-stage-probe-mutant' \
    "$STAGE_PROBE_WORKFLOW" >"$writing_stage_probe"
  run_stage_probe_fixture "$writing_stage_probe" \
    'FAIL  group-scoped stage probe writes to a host path' \
    "stage host write"
  printf 'PASS  stage host write is rejected for the intended reason\n'

  read_write_stage_probe="$fixture_root/stage-probe-read-write.yml"
  sed '/rootless_userns=/a\          exec 3<>disk-arcana-stage-probe-mutant' \
    "$STAGE_PROBE_WORKFLOW" >"$read_write_stage_probe"
  run_stage_probe_fixture "$read_write_stage_probe" \
    'FAIL  group-scoped stage probe writes to a host path' \
    "stage read-write redirection"
  printf 'PASS  stage read-write redirection is rejected for the intended reason\n'

  offhost_curl_stage_probe="$fixture_root/stage-probe-offhost-curl.yml"
  sed '/^          hostname$/i\          curl --fail --silent https://example.com/' \
    "$STAGE_PROBE_WORKFLOW" >"$offhost_curl_stage_probe"
  run_stage_probe_fixture "$offhost_curl_stage_probe" \
    'FAIL  group-scoped stage probe contains an additional network request' \
    "off-host stage probe request"
  printf 'PASS  off-host stage probe request is rejected for the intended reason\n'

  docker_accept_stage_probe="$fixture_root/stage-probe-docker-accept.yml"
  sed 's/\[\[ "$docker_socket_writable" == false \]\]/[[ "$docker_socket_writable" == true ]]/' \
    "$STAGE_PROBE_WORKFLOW" >"$docker_accept_stage_probe"
  run_stage_probe_fixture "$docker_accept_stage_probe" \
    'FAIL  group-scoped stage probe does not reject writable Docker' \
    "writable Docker acceptance"
  printf 'PASS  writable Docker acceptance is rejected for the intended reason\n'

  root_accept_stage_probe="$fixture_root/stage-probe-root-accept.yml"
  sed 's/\[\[ "$(id -u)" != 0 \]\]/[[ "$(id -u)" == 0 ]]/' \
    "$STAGE_PROBE_WORKFLOW" >"$root_accept_stage_probe"
  run_stage_probe_fixture "$root_accept_stage_probe" \
    'FAIL  group-scoped stage probe does not reject root execution' \
    "root UID acceptance"
  printf 'PASS  root UID acceptance is rejected for the intended reason\n'

  broad_sudo_stage_probe="$fixture_root/stage-probe-broad-sudo.yml"
  sed "s#\[\[ \"\${sudo_commands\[0\]}\" == '/usr/local/sbin/disk-arcana-deploy-broker --deploy \*' \]\]#[[ \"\${sudo_commands[0]}\" == *NOPASSWD* ]]#" \
    "$STAGE_PROBE_WORKFLOW" >"$broad_sudo_stage_probe"
  run_stage_probe_fixture "$broad_sudo_stage_probe" \
    'FAIL  group-scoped stage probe does not require the exact narrow sudo command' \
    "broad sudo acceptance"
  printf 'PASS  broad sudo acceptance is rejected for the intended reason\n'
fi

printf 'PASS  release workflow deploys one manifest-bound artifact through staging then production\n'
