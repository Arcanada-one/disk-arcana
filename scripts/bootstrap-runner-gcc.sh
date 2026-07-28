#!/usr/bin/env bash
# Idempotent host bootstrap: install native gcc/build-essential on self-hosted
# CI runners so disk-arcana jobs use CI_LINKER_BOOTSTRAP=native (not zig fallback).
#
# Run once per runner host as root (or via passwordless sudo):
#   sudo bash scripts/bootstrap-runner-gcc.sh
#
# CI still sources scripts/ci-ensure-cc.sh per job — this script only removes
# the need for per-job apt-get / zig bootstrap on cc-less machines.
set -euo pipefail

if command -v gcc >/dev/null 2>&1; then
  gcc --version | head -1
  echo "bootstrap-runner-gcc: gcc already present"
  exit 0
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "bootstrap-runner-gcc: apt-get not found — install gcc manually on this host" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq gcc g++ build-essential

gcc --version | head -1
echo "bootstrap-runner-gcc: installed native toolchain"
