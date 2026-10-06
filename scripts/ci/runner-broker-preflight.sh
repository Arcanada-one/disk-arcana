#!/usr/bin/env bash
# runner-broker-preflight.sh — refuse to escalate from a runner that still holds the docker group after the host
# retired it (A2-457; the check itself is SEC-0028's, from muneral/transcribator-api scripts/ci/).
#
# Why a workspace copy and not the service one: the service copy is bound to `arcanada-compose-broker` and proves its
# grant with `sudo -n <broker> <service> ps`. This repository's privileged jobs escalate through other helpers
# (gh-triage-install.sh, kb-deploy-broker, `sudo apt-get`, `sudo systemctl`, `sudo docker`), none of which has that
# interface. A2-457 named the gap: the docker-group check has to be separate from the broker check. So here:
#   * the docker-group check is ALWAYS run, exactly as SEC-0028 wrote it — armed by the host marker root creates when
#     it drops the group, so the strict check turns on at that moment and cannot be forgotten; before the marker it
#     prints a NOTE and passes;
#   * a broker is checked ONLY when a job names one (BROKER_PREFLIGHT_BIN): installed, not a symlink, not writable by
#     this account (the test that holds under an ACL), root-owned, mode 755. No service action is called — brokers
#     here do not share an interface, and a job that needs one proves its own grant.
set -euo pipefail

fail() {
  printf 'runner-broker-preflight: ERROR: %s\n' "$1" >&2
  exit 1
}

marker="${BROKER_PREFLIGHT_RETIRED_MARKER:-/etc/arcanada/docker-group-retired}"
forbidden_group="${BROKER_PREFLIGHT_FORBIDDEN_GROUP:-docker}"
broker="${BROKER_PREFLIGHT_BIN:-}"

if [[ -n "${broker}" ]]; then
  [[ -f "${broker}" ]] || fail "broker is not installed at ${broker}"
  [[ ! -L "${broker}" ]] || fail "broker path is a symlink"
  [[ -x "${broker}" ]] || fail "broker is not executable"
  [[ ! -w "${broker}" ]] || fail "broker is writable by this account"
  owner="$(stat -c '%U' -- "${broker}")"
  [[ "${owner}" == 'root' ]] || fail "broker is owned by ${owner}, not root"
  mode="$(stat -c '%a' -- "${broker}")"
  [[ "${mode}" == '755' ]] || fail "broker mode is ${mode}, expected 755"
fi

if [[ "${BROKER_PREFLIGHT_TEST_MODE:-0}" == "1" ]]; then
  effective_groups="${BROKER_PREFLIGHT_EFFECTIVE_GROUPS:-}"
else
  effective_groups="$(id -nG)"
fi

if [[ -e "${marker}" ]]; then
  case " ${effective_groups} " in
    *" ${forbidden_group} "*)
      fail "runner is still in the ${forbidden_group} group after it was retired on this host"
      ;;
  esac
else
  printf 'runner-broker-preflight: NOTE: %s absent — %s group membership not yet retired on this host\n' \
    "${marker}" "${forbidden_group}"
fi

printf 'runner-broker-preflight: group state%s checks passed\n' "${broker:+ and broker install}"
