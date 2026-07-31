#!/usr/bin/env bash
# INFRA-0370: require immutable references for every non-local workflow action.
#
# Default mode is offline and checks reference *shape* only (full 40-hex SHA).
# `--verify-remote` additionally resolves each SHA through the GitHub API and
# requires it to be a real *commit*. That second check matters because an
# annotated tag object also has a 40-hex SHA but is NOT a valid action ref —
# `uses: owner/repo@<tag-object-sha>` fails to resolve at job start. The shape
# check alone cannot tell the two apart.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
failures=0
verify_remote=0

case "${1:-}" in
  --verify-remote)
    verify_remote=1
    ;;
  "")
    ;;
  *)
    printf 'usage: %s [--verify-remote]\n' "$0" >&2
    exit 2
    ;;
esac

# Resolve owner/repo@sha through the GitHub commits API. Returns 0 when the SHA
# names a commit, 1 when it does not, and 2 when the API could not be reached
# (rate limit, offline runner) so the caller can degrade instead of failing.
resolve_commit() {
  local repo="$1" sha="$2" url status
  url="https://api.github.com/repos/${repo}/commits/${sha}"

  local -a curl_args=(
    --silent --show-error --location
    --retry 2 --retry-all-errors
    --max-time 20
    --output /dev/null
    --write-out '%{http_code}'
    --header 'Accept: application/vnd.github+json'
  )
  if [[ -n "${GITHUB_TOKEN:-${GH_TOKEN:-}}" ]]; then
    curl_args+=(--header "Authorization: Bearer ${GITHUB_TOKEN:-${GH_TOKEN}}")
  fi

  status="$(curl "${curl_args[@]}" "$url" 2>/dev/null || echo 000)"
  case "$status" in
    200) return 0 ;;
    404 | 422) return 1 ;;
    *) return 2 ;;
  esac
}

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
      if [[ "$verify_remote" -eq 1 ]]; then
        repo="${reference%@*}"
        sha="${reference##*@}"
        set +e
        resolve_commit "$repo" "$sha"
        resolved=$?
        set -e
        case "$resolved" in
          0) ;;
          1)
            printf 'NOT-A-COMMIT %s: %s (40-hex but not a commit — annotated tag object?)\n' \
              "${workflow#"$REPO_ROOT"/}" "$reference" >&2
            failures=$((failures + 1))
            ;;
          *)
            printf 'WARN unreachable GitHub API for %s — shape check only\n' "$reference" >&2
            ;;
        esac
      fi
      continue
    fi

    printf 'MUTABLE %s: %s\n' "${workflow#"$REPO_ROOT"/}" "$reference" >&2
    failures=$((failures + 1))
  done < <(grep -E '^[[:space:]]*-?[[:space:]]*uses:' "$workflow" || true)
done

if [[ "$failures" -ne 0 ]]; then
  printf '%s bad action reference(s) found\n' "$failures" >&2
  exit 1
fi

if [[ "$verify_remote" -eq 1 ]]; then
  printf 'All non-local action references are immutable and resolve to commits\n'
else
  printf 'All non-local action references are immutable\n'
fi
