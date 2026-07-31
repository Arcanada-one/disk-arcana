#!/usr/bin/env bash
# INFRA-0370: restart-limit directive-placement contract.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
UNIT_FILE="$REPO_ROOT/deploy/linux/disk-arcana-server.service"
FIXTURE_FILE="$SCRIPT_DIR/fixtures/invalid-start-limit.service"
failures=0

pass() {
  printf 'PASS  %s\n' "$*"
}

fail() {
  printf 'FAIL  %s\n' "$*" >&2
  failures=$((failures + 1))
}

section_body() {
  local section="$1"
  local file="$2"
  awk -v wanted="[$section]" '
    /^\[/ {
      active = ($0 == wanted)
      next
    }
    active { print }
  ' "$file"
}

count_key_in_section() {
  local key="$1"
  local section="$2"
  local file="$3"
  section_body "$section" "$file" | grep -Ec "^${key}=" || true
}

check_canonical_key() {
  local key="$1"
  local value="$2"
  local unit_count service_count total_count

  unit_count="$(count_key_in_section "$key" Unit "$UNIT_FILE")"
  service_count="$(count_key_in_section "$key" Service "$UNIT_FILE")"
  total_count="$(grep -Ec "^${key}=" "$UNIT_FILE" || true)"

  if [[ "$unit_count" == 1 && "$service_count" == 0 && "$total_count" == 1 ]]; then
    pass "$key occurs exactly once under [Unit]"
  else
    fail "$key placement: unit=$unit_count service=$service_count total=$total_count"
  fi

  if section_body Unit "$UNIT_FILE" | grep -Fxq "${key}=${value}"; then
    pass "$key has value $value"
  else
    fail "$key does not have required [Unit] value $value"
  fi
}

for required in "$UNIT_FILE" "$FIXTURE_FILE"; do
  if [[ ! -f "$required" ]]; then
    fail "missing required file: $required"
  fi
done

if [[ "$failures" -eq 0 ]]; then
  check_canonical_key StartLimitIntervalSec 120s
  check_canonical_key StartLimitBurst 5

  for key in StartLimitIntervalSec StartLimitBurst; do
    if [[ "$(count_key_in_section "$key" Service "$FIXTURE_FILE")" == 1 ]] &&
      [[ "$(count_key_in_section "$key" Unit "$FIXTURE_FILE")" == 0 ]]; then
      pass "negative-control fixture keeps $key only under [Service]"
    else
      fail "negative-control fixture no longer proves invalid $key placement"
    fi
  done

  if command -v systemd-analyze >/dev/null 2>&1; then
    canonical_output="$(systemd-analyze verify "$UNIT_FILE" 2>&1 || true)"
    fixture_output="$(systemd-analyze verify "$FIXTURE_FILE" 2>&1 || true)"

    if grep -Fqi 'Unknown key' <<<"$canonical_output"; then
      fail "systemd-analyze reports an unknown key in the canonical unit"
    else
      pass "systemd-analyze reports no unknown key in the canonical unit"
    fi

    if grep -Fqi 'Unknown key' <<<"$fixture_output"; then
      pass "systemd-analyze rejects the invalid-placement fixture"
    else
      fail "systemd-analyze did not distinguish the invalid-placement fixture"
    fi
  else
    printf 'WARN  systemd-analyze unavailable; structural checks remain enforced\n'
  fi
fi

if [[ "$failures" -ne 0 ]]; then
  printf '%s unit-contract check(s) failed\n' "$failures" >&2
  exit 1
fi

printf 'All unit-contract checks passed\n'
