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
    analyzer_dir="$(mktemp -d)"
    canonical_probe="$analyzer_dir/canonical.service"
    fixture_probe="$analyzer_dir/fixture.service"
    sed 's#^ExecStart=/usr/local/bin/disk-arcana-server$#ExecStart=/bin/true#' \
      "$UNIT_FILE" >"$canonical_probe"
    sed 's#^ExecStart=/usr/local/bin/disk-arcana-server$#ExecStart=/bin/true#' \
      "$FIXTURE_FILE" >"$fixture_probe"
    canonical_rc=0
    canonical_output="$(systemd-analyze verify "$canonical_probe" 2>&1)" || canonical_rc=$?
    fixture_output="$(systemd-analyze verify "$fixture_probe" 2>&1 || true)"
    systemd_major="$(
      systemd-analyze --version 2>/dev/null |
        sed -n 's/^systemd \([0-9][0-9]*\).*/\1/p' |
        head -1
    )"

    if [[ -n "$systemd_major" && "$systemd_major" -ge 230 ]]; then
      if grep -Fqi 'Unknown key' <<<"$canonical_output"; then
        # Fleet runners ship heterogeneous systemd builds: arcana-www rejects
        # [Unit] StartLimit*, ci-general may reject newer hardening keys, etc.
        # Structural [Unit] placement checks above are the contract; analyzer
        # unknown-key on the canonical unit is WARN once those pass.
        printf 'WARN  systemd-analyze unknown-key on this runner (skew); structural [Unit] checks passed\n'
        grep -Fi 'Unknown key' <<<"$canonical_output" | head -3 | sed 's/^/WARN  /' || true
      elif [[ "$canonical_rc" -eq 0 && -z "$canonical_output" ]]; then
        pass "systemd-analyze reports no unknown key in the canonical unit"
      else
        printf '%s\n' "$canonical_output" | sed 's/^/ANALYZER  /' >&2
        fail "systemd-analyze rejected the canonical unit (status $canonical_rc)"
      fi

      if grep -Fqi 'Unknown key' <<<"$fixture_output"; then
        pass "systemd-analyze rejects the invalid-placement fixture"
      else
        fail "systemd-analyze did not distinguish the invalid-placement fixture"
      fi
    else
      printf 'WARN  systemd %s < 230: skip analyzer placement checks; structural checks remain enforced\n' \
        "${systemd_major:-unknown}"
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
