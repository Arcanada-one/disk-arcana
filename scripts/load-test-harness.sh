#!/usr/bin/env bash
# DISK-0012 load harness entrypoint — tiered scanner walks (no live staging).
#
# Usage:
#   load-test-harness.sh smoke   # 1K files (fast PR gate)
#   load-test-harness.sh scale   # 10K files (G3/T6.2 scaffold)
#   load-test-harness.sh all     # smoke then scale
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
  all)
    bash scripts/load-test-scanner-smoke.sh
    bash scripts/load-test-scanner-10k.sh
    ;;
  *)
    printf 'usage: %s {smoke|scale|all}\n' "$0" >&2
    exit 2
    ;;
esac
