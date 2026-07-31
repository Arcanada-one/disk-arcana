#!/usr/bin/env bash
# INFRA-0370 — root install of the disk-arcana unit broker from a clean checkout.
# Deliberately NOT reachable from runner sudo: a runner that can re-install its
# own broker can rewrite the rules it is bound by.
set -euo pipefail
IFS=$'\n\t'
[[ "$(id -u)" -eq 0 ]] || { echo 'must run as root' >&2; exit 1; }
[[ $# -eq 1 ]] || { echo 'usage: install-disk-arcana-install-unit-broker.sh <broker_sha256>' >&2; exit 1; }

src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/disk-arcana-install-unit-broker.sh"
sudoers_src="$(dirname "$src")/disk-arcana-install-unit.sudoers"
actual="$(sha256sum "$src" | cut -d' ' -f1)"
[[ "$actual" == "$1" ]] || { echo "broker sha256 mismatch: $actual" >&2; exit 1; }

install -m 0755 -o root -g root "$src" /usr/local/sbin/disk-arcana-install-unit
install -m 0440 -o root -g root "$sudoers_src" /etc/sudoers.d/disk-arcana-install-unit
visudo -cf /etc/sudoers.d/disk-arcana-install-unit
echo "DISK_ARCANA_UNIT_BROKER_INSTALL_PASS sha256=$actual"
