#!/usr/bin/env bash
# INFRA-0370: require immutable references for every non-local workflow action.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
failures=0

shopt -s nullglob
workflow_files=(
  "$REPO_ROOT"/.github/workflows/*.yml
  "$REPO_ROOT"/.github/workflows/*.yaml
)
shopt -u nullglob

for workflow in "${workflow_files[@]}"; do
  while IFS= read -r line; do
    reference="${line#*uses:}"
    reference="${reference%%#*}"
    reference="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"$reference")"
    reference="${reference%\"}"
    reference="${reference#\"}"
    reference="${reference%\'}"
    reference="${reference#\'}"

    if [[ "$reference" == ./* ]]; then
      continue
    fi

    if [[ "$reference" == docker://* ]]; then
      if [[ "$reference" =~ @sha256:[0-9a-fA-F]{64}$ ]]; then
        continue
      fi
    elif [[ "$reference" =~ @[0-9a-fA-F]{40}$ ]]; then
      continue
    fi

    printf 'MUTABLE %s: %s\n' "${workflow#"$REPO_ROOT"/}" "$reference" >&2
    failures=$((failures + 1))
  done < <(grep -E '^[[:space:]]*-?[[:space:]]*uses:' "$workflow" || true)
done

if [[ "$failures" -ne 0 ]]; then
  printf '%s mutable action reference(s) found\n' "$failures" >&2
  exit 1
fi

printf 'All non-local action references are immutable\n'
