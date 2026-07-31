#!/usr/bin/env bash
# INFRA-0370 — narrow root broker for delivering disk-arcana-server.service.
#
# ci-runner on arcana-prod has command-scoped sudo only (not blanket sudo -n).
# This fixed-path helper is the single NOPASSWD grant for unit delivery; the
# runner supplies a checkout path and the expected unit SHA256, and the broker
# refuses anything that does not match.
#
# Bootstrap (root, once per host):
#   deploy/linux/install-disk-arcana-install-unit-broker.sh <broker_sha256>
set -euo pipefail
IFS=$'\n\t'
umask 022

readonly UNIT_NAME="disk-arcana-server.service"
readonly REL_UNIT="deploy/linux/${UNIT_NAME}"
readonly INSTALL="/usr/bin/install"
readonly SYSTEMCTL="/usr/bin/systemctl"
readonly TARGET="/etc/systemd/system/${UNIT_NAME}"
readonly HEALTH_URL="http://127.0.0.1:9446/health"
readonly EXPECT_INTERVAL="2min"
readonly EXPECT_BURST="5"

usage() {
  printf 'usage: %s --install <unit_sha256> <checkout_root>\n' "$(basename "$0")" >&2
  exit 2
}

[[ "$(id -u)" -eq 0 ]] || {
  printf 'broker must run as root\n' >&2
  exit 1
}

[[ "${1:-}" == --install ]] || usage
[[ $# -eq 3 ]] || usage

expected_sha="$2"
checkout_root="$3"
source_unit="${checkout_root%/}/${REL_UNIT}"

[[ -f "$source_unit" ]] || {
  printf 'source unit missing: %s\n' "$source_unit" >&2
  exit 1
}

actual_sha="$(sha256sum "$source_unit" | awk '{print $1}')"
[[ "$actual_sha" == "$expected_sha" ]] || {
  printf 'unit sha256 mismatch: got %s expected %s\n' "$actual_sha" "$expected_sha" >&2
  exit 1
}

backup=""
if [[ -f "$TARGET" ]]; then
  backup="${TARGET}.bak-$(date -u +%Y%m%dT%H%M%SZ)"
  cp -a "$TARGET" "$backup"
  printf 'backup: %s\n' "$backup"
fi

"$INSTALL" -o root -g root -m 0644 "$source_unit" "$TARGET"
"$SYSTEMCTL" daemon-reload
printf 'installed %s and reloaded systemd\n' "$TARGET"

"$SYSTEMCTL" restart disk-arcana-server

health_ok() {
  local body status
  for _ in $(seq 1 12); do
    if body="$(curl -sf --max-time 10 "$HEALTH_URL" 2>/dev/null)"; then
      status="$(jq -r '.status // empty' <<<"$body" 2>/dev/null || true)"
      if [[ "$status" == "ok" ]]; then
        printf '%s\n' "$body"
        return 0
      fi
    fi
    sleep 5
  done
  return 1
}

if health_ok; then
  printf 'health OK after restart\n'
else
  printf 'health check FAILED — rolling back\n' >&2
  if [[ -n "$backup" ]]; then
    cp -a "$backup" "$TARGET"
    "$SYSTEMCTL" daemon-reload
    "$SYSTEMCTL" restart disk-arcana-server
  fi
  exit 1
fi

interval="$("$SYSTEMCTL" show "$UNIT_NAME" -p StartLimitIntervalUSec --value)"
burst="$("$SYSTEMCTL" show "$UNIT_NAME" -p StartLimitBurst --value)"
printf 'loaded StartLimitIntervalUSec=%s StartLimitBurst=%s\n' "$interval" "$burst"

bad=0
[[ "$interval" == "$EXPECT_INTERVAL" ]] || bad=1
[[ "$burst" == "$EXPECT_BURST" ]] || bad=1
exit "$bad"
