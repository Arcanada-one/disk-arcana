#!/usr/bin/env bash
# INFRA-0370: manifest-bound bundle preflight and validator contract.
#
# This is deliberately limited to a local bundle boundary. It does not copy,
# activate, deploy, provision, or roll back anything on a host. The bundle
# inventory is fixed and the manifest is the only generated artifact.
#
# create --root ROOT --commit SHA
#   Validate the input members, then atomically create manifest.sha256.
#
# verify --root ROOT --expected-commit SHA
#   Read-only validation of the exact inventory, commit identity, and hashes.
#
# The resulting slice advances INFRA-0370 but does not close its deployment,
# live-staging, rollback, or runbook requirements.

set -euo pipefail

export LC_ALL=C

MANIFEST_NAME="manifest.sha256"
COMMIT_MEMBER="commit"

# Keep this list byte-sorted. The order is part of the deterministic manifest
# contract; manifest.sha256 itself is intentionally excluded.
REQUIRED_MEMBERS=(
  commit
  deploy-server-broker.sh
  deploy-server.sh
  disk-arcana-deploy.sudoers
  disk-arcana-server
  disk-arcana-server.service
  install.sh
  provision-deploy-broker.sh
)

ROOT=""
COMMIT=""
EXPECTED_COMMIT=""
TEMP_MANIFEST=""

usage() {
  cat <<'USAGE'
usage:
  validate-deploy-bundle.sh create --root ROOT --commit SHA
  validate-deploy-bundle.sh verify --root ROOT --expected-commit SHA
USAGE
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "${TEMP_MANIFEST:-}" ]]; then
    rm -f -- "$TEMP_MANIFEST"
  fi
}

trap cleanup EXIT

[[ $# -ge 1 ]] || {
  usage >&2
  exit 2
}

if [[ "$1" == --help || "$1" == -h ]]; then
  usage
  exit 0
fi

MODE="$1"
shift

case "$MODE" in
  create|verify)
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      [[ $# -ge 2 ]] || die "--root requires a value"
      ROOT="$2"
      shift 2
      ;;
    --commit)
      [[ $# -ge 2 ]] || die "--commit requires a value"
      COMMIT="$2"
      shift 2
      ;;
    --expected-commit)
      [[ $# -ge 2 ]] || die "--expected-commit requires a value"
      EXPECTED_COMMIT="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$ROOT" ]] || die "--root is required"

# Prefix relative roots so a directory whose name begins with '-' cannot be
# parsed as a find expression. Keep the caller's path semantics while making
# the traversal argument unambiguously a path.
if [[ "$ROOT" != /* ]]; then
  ROOT="$PWD/$ROOT"
fi

if [[ "$MODE" == create ]]; then
  [[ -n "$COMMIT" ]] || die "create requires --commit"
  [[ -z "$EXPECTED_COMMIT" ]] || die "create does not accept --expected-commit"
  EXPECTED_COMMIT="$COMMIT"
else
  [[ -n "$EXPECTED_COMMIT" ]] || die "verify requires --expected-commit"
  [[ -z "$COMMIT" ]] || die "verify does not accept --commit"
fi

[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  die "expected commit must be exactly 40 lowercase hexadecimal characters"

if [[ -L "$ROOT" || ! -d "$ROOT" ]]; then
  die "bundle root is not a non-symlink directory: $ROOT"
fi

is_required_member() {
  local candidate="$1"
  local member
  for member in "${REQUIRED_MEMBERS[@]}"; do
    if [[ "$candidate" == "$member" ]]; then
      return 0
    fi
  done
  return 1
}

validate_regular_member() {
  local member="$1"
  local path="$ROOT/$member"

  if [[ -L "$path" ]]; then
    die "member is a symlink: $member"
  fi
  if [[ ! -f "$path" ]]; then
    die "member is not a regular file: $member"
  fi
}

validate_inventory() {
  local path member inventory_status inventory_marker inventory_count i
  local -a inventory=()

  # Only the fixed top-level members plus the generated manifest are allowed.
  # find does not follow symlinks here; a symlink with an allowed name is
  # rejected by validate_regular_member below.
  # Keep the traversal result out of the bundle itself. The marker is emitted
  # only after find exits successfully, so process-substitution status cannot
  # turn an enumeration failure into an accepted partial inventory.
  inventory_marker="__disk_arcana_inventory_success__"
  inventory_status=0
  mapfile -d '' -t inventory < <(
    find "$ROOT" -mindepth 1 -maxdepth 1 -print0 || inventory_status=$?
    if (( inventory_status == 0 )); then
      printf '%s\0' "$inventory_marker"
    fi
  )
  inventory_count=${#inventory[@]}
  if (( inventory_count == 0 )) ||
    [[ "${inventory[$((inventory_count - 1))]}" != "$inventory_marker" ]]; then
    die "could not enumerate bundle inventory"
  fi

  for ((i = 0; i < inventory_count - 1; i++)); do
    path="${inventory[i]}"
    member="${path##*/}"
    if [[ "$member" == "$MANIFEST_NAME" ]]; then
      continue
    fi
    if ! is_required_member "$member"; then
      die "extra top-level bundle member: $member"
    fi
  done

  for member in "${REQUIRED_MEMBERS[@]}"; do
    if [[ ! -e "$ROOT/$member" && ! -L "$ROOT/$member" ]]; then
      die "missing bundle member: $member"
    fi
    validate_regular_member "$member"
  done
}

validate_commit_member() {
  local commit_path="$ROOT/$COMMIT_MEMBER"
  local actual_commit

  validate_regular_member "$COMMIT_MEMBER"
  if ! actual_commit="$(
    awk '
      NR == 1 { first = $0 }
      NR > 1 { too_many = 1 }
      END {
        if (NR != 1 || too_many) exit 1
        print first
      }
    ' "$commit_path"
  )"; then
    die "commit member must contain exactly one commit line"
  fi
  [[ "$actual_commit" =~ ^[0-9a-f]{40}$ ]] ||
    die "commit member is not a 40-character lowercase hexadecimal SHA"
  [[ "$actual_commit" == "$EXPECTED_COMMIT" ]] ||
    die "commit identity mismatch: expected $EXPECTED_COMMIT, found $actual_commit"
}

validate_manifest_file() {
  local manifest_path="$ROOT/$MANIFEST_NAME"
  local line line_number=0 digest member actual_digest expected_member
  declare -A seen=()

  validate_regular_member "$MANIFEST_NAME"

  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    if [[ ! "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([^[:space:]]+)$ ]]; then
      die "malformed manifest line $line_number"
    fi
    digest="${BASH_REMATCH[1]}"
    member="${BASH_REMATCH[2]}"

    if ! is_required_member "$member"; then
      die "manifest names an unknown member: $member"
    fi
    if (( line_number > ${#REQUIRED_MEMBERS[@]} )); then
      die "manifest contains too many members"
    fi
    if [[ -n "${seen[$member]+present}" ]]; then
      die "manifest contains duplicate member: $member"
    fi
    seen["$member"]=1
    expected_member="${REQUIRED_MEMBERS[$((line_number - 1))]}"
    if [[ "$member" != "$expected_member" ]]; then
      die "manifest member order mismatch at line $line_number: expected $expected_member, found $member"
    fi

    actual_digest="$(sha256sum -- "$ROOT/$member" | awk '{print $1}')"
    if [[ "$actual_digest" != "$digest" ]]; then
      die "manifest hash mismatch for member: $member"
    fi
  done <"$manifest_path"

  if [[ "$line_number" -ne "${#REQUIRED_MEMBERS[@]}" ]]; then
    die "manifest member count mismatch: expected ${#REQUIRED_MEMBERS[@]}, found $line_number"
  fi

  for member in "${REQUIRED_MEMBERS[@]}"; do
    if [[ -z "${seen[$member]+present}" ]]; then
      die "manifest is missing member: $member"
    fi
  done
}

validate_inputs() {
  validate_inventory
  validate_commit_member
}

create_manifest() {
  local member digest

  # All prechecks happen before this temporary file is created. A rejected
  # bundle therefore cannot replace an existing manifest or leave a marker in
  # the target tree.
  TEMP_MANIFEST="$(mktemp "$ROOT/.manifest.sha256.tmp.XXXXXX")" ||
    die "could not create a temporary manifest"

  for member in "${REQUIRED_MEMBERS[@]}"; do
    digest="$(sha256sum -- "$ROOT/$member" | awk '{print $1}')"
    printf '%s  %s\n' "$digest" "$member" >>"$TEMP_MANIFEST"
  done

  mv -f -- "$TEMP_MANIFEST" "$ROOT/$MANIFEST_NAME"
  TEMP_MANIFEST=""
}

case "$MODE" in
  create)
    validate_inputs
    manifest_path="$ROOT/$MANIFEST_NAME"
    if [[ -e "$manifest_path" || -L "$manifest_path" ]]; then
      validate_regular_member "$MANIFEST_NAME"
    fi
    create_manifest
    printf 'bundle manifest created: %s\n' "$manifest_path"
    ;;
  verify)
    validate_inputs
    validate_manifest_file
    printf 'bundle preflight passed: %s\n' "$ROOT"
    ;;
esac
