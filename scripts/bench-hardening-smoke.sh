#!/usr/bin/env bash
# DISK-0012 criterion smoke — quick sample for local/CI sanity (not full bench).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
cargo bench -p disk-core --bench hardening -- --sample-size 10
