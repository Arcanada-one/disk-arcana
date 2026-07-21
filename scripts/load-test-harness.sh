#!/usr/bin/env bash
# DISK-0012 load harness entrypoint — local tiers (no live staging).
#
# Usage:
#   load-test-harness.sh smoke   # 1K scanner walk
#   load-test-harness.sh scale   # 10K scanner walk
#   load-test-harness.sh sync    # 3-node gRPC round-trip
#   load-test-harness.sh all     # smoke + scale + sync
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

tier="${1:-smoke}"
case "$tier" in
  smoke)
    bash scripts/load-test-scanner-smoke.sh
    ;;
  scale)
    bash scripts/load-test-scanner-10k.sh
    ;;
  sync)
    bash scripts/load-test-sync-smoke.sh
    ;;
  all)
    bash scripts/load-test-scanner-smoke.sh
    bash scripts/load-test-scanner-10k.sh
    bash scripts/load-test-sync-smoke.sh
    ;;
  *)
    printf 'usage: %s {smoke|scale|sync|all}\n' "$0" >&2
    exit 2
    ;;
esac
