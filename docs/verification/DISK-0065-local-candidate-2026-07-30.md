# DISK-0065 local candidate verification

Verified at `2026-07-30T20:10:00Z` (round 3 — three narrow blocker corrections
from independent rereview). Round 4 extends the candidate with rename-mode
mapping, drop-watchdog, and report-overclaim corrections (see § Round-4).

## Identity

- Repository: `Arcanada-one/disk-arcana`
- Branch: `fix/DISK-0065-windows-ci`
- Base `HEAD`: `41cc2c447c5f4ea47ca5ea84b02ba318d82a914f`
- Six-file product/test diff SHA-256 before round-1 evidence:
  `3bbbfa29a5477080e8185634812780676ec132421975c4a5cf5f7608edf08cbb`
- Round-1 verification-report SHA:
  `9e7eb0c2c0cff227a4f94b7a0d74bbe0b802c16b6003c5d87928528148e41200`
- Round-2 diff SHA-256 (this evidence — tests rewritten, product unchanged):
  `e3b495ac9225391bedcbbc2301d30840f2b8e03207a6d356f1199c84d4d0e366`
- This report's identity is its Git blob hash (`git hash-object` on the
  untracked working-tree file); no self-referential SHA is embedded — the
  report text can change without invalidating its own identity claim.
- Round-3 diff SHA-256 (this evidence — three narrow blocker corrections,
  product logic unchanged):
  `0bf4693005846913e987e7307895ebe1e5e0a6db2126c876bbb069f72528d303`
- Round-4 diff SHA-256 (this evidence — rename-mode mapping fix,
  drop-watchdog replacement, report-overclaim corrections):
  `5db3a823c7b46907586a2a86887a827ec409e6f22dd5cd0abbfaf19c3403986f`
- Product/test diff: 2433 insertions, 90 deletions (6 files)

The candidate is uncommitted at this checkpoint. Windows CI, feature PR,
repository rule readback, merge and exact merged-main proof remain open.

## Round-3 corrections (independent rereview)

Three blockers identified in an independent rereview of the round-2
candidate are closed below.

### Blocker A — deterministic handle-drop saturation proof

The round-2 `share_index_handle_drop_under_saturation_completes` wrote 300
files into a 256-capacity channel and slept 1.5 s, hoping saturation would
occur.  It did not force a specific backend, did not observe the saturation
flag or `TrySendError::Full`, and the loop actively drained the channel.

**Round-3 fix:** Forces `arm_poll_watcher` (no native escape), uses a
capacity-1 channel pre-filled with a sentinel so every subsequent callback
`try_send` MUST return `TrySendError::Full`, spin-waits for the saturation
flag with a bounded deadline (5 s, 10 ms poll), spawns the consumer loop
latched behind the full channel, builds `ShareIndexHandle` directly
(same-crate, private fields visible), then drops on the current thread and
asserts bounded completion (<5 s).  No timing-only sleep is used as proof.

### Blocker B — cross-vault test claim correction

The round-2 `saturation_reconcile_respects_vault_isolation` claimed vault "b"
was "completely unchanged — no cross-vault mutation."  Production
`full_reconcile` intentionally covers every configured canonical root, so
vault "b" IS reconciled — the old claim was false.

**Round-3 fix:** Renamed to `cross_vault_reconcile_no_misattribution`.
Preserves the global-all-root production contract.  Asserts vault "b"'s
row preserves its original content hash and size (correct reconciliation —
global reconcile may update inode and mtime; content identity is what
matters), adds explicit cross-vault negative assertions (no A-owned
path appears under B, no B-owned path appears under A), while A/B
ownership and deletion semantics remain correct.  No production behavior
changed.

### Blocker C — self-referential verification-report SHA

The round-2 report embedded its own SHA-256 (`98161c...`), which is
logically self-referential — the SHA changes when the report text changes.

**Round-3 fix:** Removed the embedded self-SHA.  The report's identity is
now its Git blob hash (`git hash-object`), computable independently
without self-reference.

## Round-4 corrections (rename mapping + drop watchdog + report overclaims)

Three rereview blockers are closed below: two product/test issues (D–E)
and one report-accuracy issue (F).

### Blocker D — rename-mode mapping (From → Delete/Tombstone, To → Change/Upsert)

Both `translate_notify_event` functions (client and server) treated
`EventKind::Modify(ModifyKind::Name(_))` as Upsert/Change.  The From
path of a rename — where the file no longer exists — was incorrectly
upserted instead of tombstoned.  The To path was correctly mapped
(already upsert).  `RenameMode::Both` (single event carrying both paths
in From-then-To order) was also incorrect for the first path.

**Round-4 fix:** Client maps `RenameMode::From` → `Delete`, `To` →
`Change`, and `Both` path\[0\] → `Delete` / path\[1\] → `Change`.  Server
maps analogously to `Tombstone` / `Upsert`.  Six new unit tests (three
client, three server — the To cases were already passing and are retained
as explicit regression anchors) and two
integration tests (within-vault rename, cross-vault move) prove:
vanished old path is tombstoned, new path is upserted to the correct
vault, and no cross-vault misattribution occurs.  The global all-root
reconcile semantics are preserved (no production contract changed).

### Blocker E — synchronous drop timing assertion replaced with external watchdog

The round-3 `share_index_handle_drop_under_saturation_completes` asserted
`drop_elapsed < Duration::from_secs(5)` — a synchronous timing assertion
on the current thread.  If `ShareIndexHandle::drop` were to deadlock, the
test thread would hang indefinitely without producing a test failure.

**Round-4 fix:** Drop runs on a dedicated `std::thread` with a
`std::sync::mpsc::channel` sentinel.  The test thread waits on
`recv_timeout(Duration::from_secs(5))`.  If drop deadlocks, the timeout
fires and the test fails with a clear error.  If the spawned thread
panics during drop, the channel disconnects without a send, and
`recv_timeout` returns `Err(Disconnected)` — also a test failure.
This is the negative-control structure required by the proof: a deadlock
produces a test failure, not an indefinite hang.  All other deterministic
properties (forced PollWatcher, capacity-1 pre-filled channel, observed
saturation flag, consumer latched behind full channel) are preserved.

### Blocker F — report overclaims corrected

Five overclaims in the round-3 report:

1. **"checked-in file"** — the report file is untracked (`docs/verification/`
   is not in the repository).  Fixed to "untracked working-tree file".
2. **"same metadata as the seed"** in Blocker B — global reconcile may
   update inode and mtime; content hash and size are what the test asserts.
   Fixed to "preserves its original content hash and size."
3. **"unchanged"** in the round-2 cross-vault description — contradicts
   the round-3 correction confirming vault "b" IS reconciled.  The
   round-2 narrative now cross-references Blocker B.
4. **"NOT primary failure log"** — ungrammatical.  Fixed to "primary
   Windows CI failure log."
5. **Stale test names** — historical sections reference old names for
   context; current report sections use current names.

Windows causality remains UNKNOWN. Dependency gates remain owned by
DISK-0066. No self-referential SHA is embedded.

## Round-2 corrections

Four proof gaps identified in the round-1 test suite are closed below.
Every overstated claim in the round-1 report is corrected to the exact
proof the rewritten test delivers.

## Behavior under review

- Client config and server share-index watchers first attempt the native
  backend, then create a fresh polling backend after native construction or
  watch-registration failure.
- Dual-backend failure returns a typed error.
- Configured server roots acknowledge watcher readiness before the server
  starts accepting work.
- A configured unavailable share root propagates the typed watcher error and
  aborts the server binary before it listens.
- Polling compares file contents and uses the bounded one-second interval
  required by the hot-reload contract.
- Shutdown aborts the share-index loop, unparks watcher threads and joins them.

## Five numbered proof-area closures

The numbered list below contains five proof areas. The six lettered
rereview blockers A–F above are corrections within those areas and the
verification report, not a sixth numbered proof area.

### Blocker 1 — fail-closed reconciliation

`walk_files` returns `Result<Vec<PathBuf>, ShareIndexError>`. Every `read_dir`,
`file_type` or iteration error aborts the entire walk with a typed error.
`full_reconcile` runs all filesystem walks AND all DB-list queries in phase 1
before any `upsert`/`tombstone` mutation in phase 2. A deterministic negative
control (`walk_files_fails_on_unreadable_subtree`) removes read permission on a
subdirectory and asserts `walk_files` returns `Err`. A second test
(`full_reconcile_leaves_db_unchanged_on_walk_failure`) proves a seed row in a
clean vault survives unreconciled when a sibling vault's walk fails — no partial
mutation.

### Blocker 2 — never follow symlinks

All three recursive-walk entry points (`walk_files_impl`, `resolve_existing_file`,
`upsert_local_file`) use `symlink_metadata` / `file_type().is_symlink()` checks and
reject symlink files and directories without following them. Every accepted
regular file is canonicalized and proven to reside under the configured canonical
directory. Two Unix-only integration tests prove a symlink file and a symlink
directory pointing outside the root are skipped with zero MetaDb mutation for the
escape target.

### Blocker 3 — real `run_index_loop` saturation path (corrected)

The round-1 test covered only create + delete. The corrected test
`run_index_loop_saturation_reconciles_autonomously` now covers create,
**modify**, and delete — three mutation classes through a single bounded
channel.  A seeded file is rewritten (same-length modify) while the
capacity-1 channel is pre-filled; the saturation flag drives
`full_reconcile` autonomously; all three mutations are independently
asserted in MetaDb.  Shutdown is no longer discard-timeout — the test
drops the watcher and sender, then awaits `loop_handle` and asserts
`run_index_loop` returns `Ok(())` (channel closed → clean exit) within
a 5-second bounded timeout.

The cross-vault isolation test was restructured end-to-end: it arms a
real `PollWatcher` for vault "a" with a capacity-1 pre-filled channel,
performs filesystem mutations (create + delete), confirms the saturation
flag is raised by dropped events, then drives through the real
`run_index_loop` with both vaults "a" and "b" in `canonical_roots`.
Vault "b"'s seed row preserves its original content hash and size (the
round-2 "unchanged" wording was corrected in round 3 — see Blocker B:
`full_reconcile` processes every canonical root, so vault "b" IS
reconciled; what matters is that the reconciliation is correct).  The
isolation claim is driven through the watcher → channel → loop path,
not through a direct `full_reconcile` call.

### Blocker 4 — forced PollWatcher same-size/same-mtime rewrite (corrected)

The round-1 test `share_index_loop_detects_same_size_mtime_content_change_in_metadb`
used `spawn_share_index_watcher` which tries native first; on a Linux host
with functioning inotify the native watcher could satisfy the content-change
assertion without ever exercising `PollWatcher::with_compare_contents(true)`.
The corrected test `poll_watcher_detects_same_size_mtime_content_change_in_metadb`
**forces `PollWatcher`** by calling `arm_poll_watcher` directly — no native
fallback path exists.  The watcher thread signals readiness with
`WatcherBackend::Poll` and the test asserts the backend is `Poll` before
proceeding.  The rest of the proof is unchanged: write initial content, wait
for MetaDb index, rewrite with same-length content and restored mtime, then
poll-wait for the MetaDb `content_hash` to change to the new hash — proving
`with_compare_contents(true)` detects content rewrites invisible to
metadata-only watchers.

The client-side counterpart
(`poll_watcher_detects_same_size_mtime_content_rewrite` in
`crates/disk-client/src/watcher/mod.rs`) uses `fallback_poll_config()` and
`PollWatcher::new` directly — it was already forcing PollWatcher in round 1
and is unchanged.

### Blocker 5 — deterministic handle drop + multi-root + dual-failure (corrected)

The round-1 test `share_index_handle_drop_under_saturation_completes` claimed
"under saturation conditions" but only created a handle, slept 150 ms, and
dropped — no saturation was ever induced and the claim was overstated.  The
round-2 correction wrote 300 files in a burst into the 256-capacity channel
and slept 1.5 s, but did not force a PollWatcher backend and did not observe
the saturation flag or `TrySendError::Full` — the loop could drain the channel
concurrently.  **Round 3 superseded this with a deterministic test-only seam**
(see Round-3 Blocker A above): forced PollWatcher, capacity-1 pre-filled
channel, directly observed saturation flag, and consumer latched behind the
full channel. **Round 4 supersedes the round-3 synchronous drop mechanism
with the dedicated-thread `recv_timeout` watchdog described in Blocker E.**

`multi_root_watchers_both_armed_and_produce_events` configures two roots, spawns
a shared watcher, writes to both vaults, and asserts each file is independently
indexed in MetaDb (unchanged from round 1).

`arm_watcher_dual_failure_returns_both_errors` injects paired native+poll
failures and asserts both error messages surface (unchanged from round 1).

## Fresh local gates (round 4 — rename mapping and drop watchdog)

All commands below ran from the round-4 identity above. Test counts include
the rename-mode regression tests and all unchanged earlier-round tests.

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo test -p disk-client watcher` | 21 passed, 0 failed, 0 ignored |
| `cargo test -p disk-server share_index --lib` | 22 passed, 0 failed, 0 ignored |
| `cargo test -p disk-server --test share_index_watcher` | 5 passed, 0 failed, 0 ignored |
| `cargo test -p disk-server --test it_main_boot_wiring` | 4 passed, 0 failed, 0 ignored |
| `cargo test --workspace --all-features` | exit 0; all executed tests passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | exit 0 |
| `cargo build --workspace --release` | exit 0 |
| `git diff --check` | exit 0 (no whitespace errors) |
| gitleaks on tracked diff and this report | no leaks found |

The focused client command also executed the real
`fs_watcher_emits_change_on_create` integration test. The full workspace
command executed the current rename, saturation, isolation, PollWatcher, and
drop-watchdog tests alongside every existing server, client, core, and proto
test — zero regressions.
The four binary boot wiring tests including
`configured_unavailable_share_root_aborts_binary_startup` all passed.

## Security-gate finding

The final dependency gate is not green:

- `cargo audit` reports `RUSTSEC-2026-0194` and `RUSTSEC-2026-0195` for
  inherited `quick-xml` `0.39.4`.
- `cargo deny check` additionally reports unmaintained `ttf-parser` `0.25.1`
  (`RUSTSEC-2026-0192`) and yanked `spin` `0.9.8`.

The same two `cargo audit` findings reproduce on the unchanged exact base.
They are not introduced by the watcher candidate. ARCA-0194 round 6 registers
their mandatory closure separately as collision-clear `DISK-0066` / `R6-17`;
they must not be suppressed or lost when this branch is integrated.

## Non-claims

This local checkpoint does not recover the unavailable primary Windows failure
log and does not claim that the inherited watcher exhaustion was that Windows
failure's cause. It does not establish Windows success, protected integration,
deployment applicability or epic completion. Those gates remain explicit in
the canonical `DISK-0065` task and ARCA-0194 `R6-14`.

**Windows causality remains UNKNOWN.** The primary Windows CI failure log
is unavailable; the hypothesis that an inherited watcher-notify exhaustion
caused the Windows CI failure is not proven. The five numbered proof-area
blockers are closed, including the six lettered A–F rereview corrections,
with no false leak/deadlock claim.

## Deployment gates (conditional)

Windows CI re-run, cross-compile artifact smoke, ruleset readback against the
exact main merge base, and exact merged-main CI proof remain explicitly open.
The five numbered proof-area closures, including all six A–F rereview
corrections, are a necessary but not sufficient condition for branch
integration. Condition: all four deployment gates pass → merge; any gate
fails → root-cause and re-verify.
