# DISK-0098 — receive-only safety verification (2026-08-13)

## Scope

The 2026-08-13 incident showed a receive-only Mac share being handled by a
`server-wins` path while Disk Arcana was reconciling an E2EE hash mismatch. The
repair is fail-closed: receive-only cannot be used as authority to overwrite
divergent local bytes, delete local files, or tombstone the canonical server
row.

## Changes verified

- The client refuses an unexpected `conflicts` response for a receive-only
  share and leaves the local file untouched.
- The client refuses `to_delete` for a receive-only share and leaves the local
  file untouched.
- The client applies `to_download` only when an existing local file is equal to
  the trusted baseline or already equal to the remote bytes; an unknown or
  divergent file produces `receive_only.safety_blocked`.
- The server suppresses receive-only delete/upload-side actions, does not
  tombstone the canonical row for a missing receive-only path, and retains the
  canonical conflict copy as a download candidate.

## Evidence

From the isolated worktree `fix/disk-0098-receive-only-safety` at `fb7fc1b`:

```text
cargo fmt --all -- --check                         PASS
cargo test -p disk-client --lib                    166 passed
cargo test -p disk-client --test it_conflict_cycle 7 passed
cargo test -p disk-client --test it_upload_hardening 8 passed
cargo test -p disk-server --test acl_role_mismatch 6 passed
```

The full `cargo test --workspace --all-features` run reached the existing
`share_index_watcher` suite and reproduced two unrelated failures in the
pre-existing rename/cross-vault tests. No share-index source was changed by
this repair; the focused client/server safety suites above are green.

## Deployment gate

This branch is not deployed. Disk Arcana remains disabled on Mac,
`arcana-devs`, `arcana-agents`, and `arcana-prod` under the operator hold from
the incident. Re-enable requires a reviewed build, a fresh MetaDB/filesystem
backup, a dry-run reconciliation, and a second-pass `revived=0` check on the
canonical host.
