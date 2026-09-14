#!/usr/bin/env bash
# INFRA-0370: fail closed unless a fresh remote read shows the built SHA is main.

set -euo pipefail
IFS=$'\n\t'

expected_sha="${1:-}"
remote="${2:-origin}"

[[ "$expected_sha" =~ ^[0-9a-f]{40}$ ]] || {
  printf 'ERROR: expected SHA must be 40 lowercase hexadecimal characters\n' >&2
  exit 2
}
[[ -n "$remote" ]] || {
  printf 'ERROR: remote must not be empty\n' >&2
  exit 2
}

readback="$(git ls-remote --exit-code "$remote" refs/heads/main)" || {
  printf 'ERROR: could not read fresh origin/main\n' >&2
  exit 1
}
remote_main_sha="$(printf '%s\n' "$readback" | awk '
  $2 == "refs/heads/main" && $1 ~ /^[0-9a-f]{40}$/ {sha=$1; count++}
  END {if (count != 1) exit 1; print sha}
')" || {
  printf 'ERROR: origin/main readback was ambiguous or malformed\n' >&2
  exit 1
}

[[ "$remote_main_sha" == "$expected_sha" ]] || {
  printf 'ERROR: built SHA is stale relative to fresh origin/main\n' >&2
  exit 1
}

printf 'fresh_main_sha=%s\n' "$remote_main_sha"
