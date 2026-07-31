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

**Superseded status note (round 6, 2026-07-31).** The sentence that stood here
— "the candidate is uncommitted at this checkpoint; Windows CI, feature PR,
repository rule readback, merge and exact merged-main proof remain open" — was
true when written and is now false. The candidate is committed
(`bd78558`, `2529c08`, `ac0e05d`) and merged via pull request 126 as
`cffed529994e5f11586e13d6dabe6a991537c049`. Each of the four deployment gates
was then re-verified independently in round 6 rather than inferred from the
merge; see § Round-6 closure for the evidence behind each one, and
§ Round-6 closure → "What round 6 does NOT close" for what remains open.

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

**Round-6 addendum.** Re-verified on merged `main` (`cffed52`) with
`cargo-audit 0.22.2`: all four findings still reproduce, plain `cargo audit`
still exits 1, and none was suppressed by this lane. The repository's
`Lint (fmt + clippy + audit + deny)` check is nevertheless green, because that
check is narrower than the commands in this section — see § Round-6 closure →
"What round 6 does NOT close" for the exact mechanism. **A green `Lint` does not
mean this dependency gate is green.**

## Round-5 authoritative Windows CI finding

Pull request 126 reached the self-hosted
`windows-x86_64-pc-windows-msvc` test job. The watcher rename tests passed,
including `From`, `To`, and `Both`. The job then exposed a Windows-only test
harness defect: `poll_watcher_detects_same_size_mtime_content_rewrite` opened
the fixture file read-only before `File::set_modified`, and Windows returned
`ERROR_ACCESS_DENIED` because setting file time requires a write-capable
handle.

The minimal correction uses `OpenOptions::write(true)` for that fixture handle.
This does not change product watcher behavior. The failed run remains preserved
as negative evidence; a new Windows run is required before merge.

The next exact-head run, `30584969669`, proved that the client-side fixture
correction worked, then exposed the same read-only-handle defect in two
server-side fixtures. Its third failure was a multi-root Windows indexing miss.
A candidate diagnosis is inconsistent path identity:
`spawn_share_index_watcher` armed native watchers with the caller's path while
the index loop used its canonical spelling. On Windows those spellings can
differ by the verbatim-path prefix, which can make translated events fail the
root-prefix filter. The correction opens both server fixtures with a
write-capable handle and arms each backend with the same canonical root owned by
the index loop. This is a cross-platform path-identity invariant, not a timing
increase or Windows-only skip; only a fresh Windows run can prove that it closes
the observed indexing miss.

## Round-6 closure

Round 6 closes the lane. The candidate is merged, the four deployment gates
named below are individually evidenced, and the Windows failure now has a proven
cause rather than a hypothesis.

### Merge record

| Field | Value |
|---|---|
| Pull request | 126 — `fix(watcher): preserve Windows rename semantics` |
| Head branch | `fix/DISK-0065-windows-ci` |
| Commits | `bd78558`, `2529c08`, `ac0e05d` |
| Exact base | `41cc2c447c5f4ea47ca5ea84b02ba318d82a914f` |
| Merge commit | `cffed529994e5f11586e13d6dabe6a991537c049` |
| Merged at | `2026-07-30T22:28:54Z` by `Arcanada` |

### Windows causality — RESOLVED (supersedes the earlier UNKNOWN)

Rounds 3–5 recorded "Earlier Windows causality remains UNKNOWN" because the
primary failure log was believed unavailable. **The log was retrieved in round 6**
and the cause is now proven rather than hypothesised. The round-5 candidate
diagnosis ("inconsistent path identity") is confirmed correct; the older
inherited-watcher-exhaustion hypothesis is not supported and is withdrawn.

Failing job `90275566736` (run `30359528906`, 2026-07-28) on the
`windows-x86_64-pc-windows-msvc` runner. Every suite reported `ok` except one;
the `Test` step failed on a single assertion:

```
---- share_index_watcher_tombstones_on_delete stdout ----
thread 'share_index_watcher_tombstones_on_delete' panicked at
crates\disk-server\tests\share_index_watcher.rs:103:5:
MetaDb tombstone for gone.txt not written within deadline
test result: FAILED. 1 passed; 1 failed; 0 ignored
error: test failed, to rerun pass `-p disk-server --test share_index_watcher`
```

**Root cause.** `spawn_share_index_watcher` armed its notify backends from the
caller's `share_roots` while `run_index_loop` resolved and filtered events
against `canonical_roots`. On Windows `canonicalize()` returns a verbatim
extended-length path (`\\?\C:\...`) whose spelling differs from the raw path, so
`strip_prefix(canonical_root)` failed for every translated event and the events
were discarded before reaching the index — silently, with no error and no
dropped-event signal. The delete therefore never produced a tombstone and the
test ran to its deadline. On Linux the two spellings normally coincide, which is
why the defect stayed latent there and surfaced only on Windows.

**Fix.** `ac0e05d` arms every backend from `canonical_roots`, unifying path
identity across registration, the index loop, the event root lookup and
`full_reconcile`. This is a cross-platform invariant repair — not a timing
increase, not a Windows-only skip, and not a test-only change. Separately,
`2529c08` and the fixture hunks of `ac0e05d` correct three mtime fixtures to
open with `OpenOptions::write(true)`, because Windows `SetFileTime` rejects a
read-only handle with `ERROR_ACCESS_DENIED`.

Causality is resolved for the 2026-07-28 failure specifically. No claim is made
about any earlier Windows failure whose log has since expired.

### Independent regression confirmation

Dependabot pull request 123 (`actions/setup-node` 4 → 7) changes no Rust source
at all, which makes it a clean control:

| Run | Head | Date | `windows-x86_64-pc-windows-msvc` |
|---|---|---|---|
| `30294421701` | `9defa1ab` | 2026-07-27 | success (pre-regression) |
| `30359528906` | `cc22f011` | 2026-07-28 | **failure** — `tombstones_on_delete` |
| `30620984379` | `b2087758` | 2026-07-31 | **success** — after rebase onto merged `main` |

PR 123 changed nothing of its own between the failing and the passing run; the
only difference is that its base now contains `cffed52`. An unrelated branch
recovering purely by rebasing onto the fix is third-party evidence that the fix
closed the regression, independent of this lane's own test suite.

*Note on `9defa1ab`:* dependabot force-pushes on rebase, so that commit is no
longer reachable from the branch and `git cat-file -t 9defa1ab` fails in a local
clone. It is not fabricated — it resolves via the GitHub API
(`repos/Arcanada-one/disk-arcana/commits/9defa1ab…`) and is recorded as the
authoritative `head_sha` of run `30294421701`. The branch head is now
`b2087758`. Cite the run ID rather than the SHA when reproducing this table.

### Deployment gate closure

| # | Gate | Evidence | Result |
|---|---|---|---|
| 1 | Windows CI re-run | PR 126, run `30586148753`, job `windows-x86_64-pc-windows-msvc`, 18m07s | **pass** |
| 2 | Cross-compile artifact smoke | local `x86_64-unknown-linux-gnu` + `aarch64-unknown-linux-gnu` release builds — see § Round-6 cross-compile artifact smoke | **pass** |
| 3 | Ruleset readback vs exact merge base | ruleset `20080518` `main-pr-ci-integrity`; rule-suite `3510158827`, `before_sha` `41cc2c44`, `after_sha` `cffed52`, `result: pass` | **pass** |
| 4 | Exact merged-main CI proof | on `cffed52`: run `30587283116` (CI — 5/5 jobs success) and run `30587283085` (Windows — success) | **pass** |

**Gate 3 detail.** The ruleset was read back at *both* of its versions rather
than only the current one, because its `updated_at` (`22:28:33Z`) falls 21
seconds before the merge (`22:28:54Z`), and a last-moment weakening would have
invalidated the gate. It was strengthened, not weakened. Version `44934569`
(21:32Z) already carried all six required checks — including
`windows-x86_64-pc-windows-msvc` — with
`strict_required_status_checks_policy: true` and an empty `bypass_actors`. The
22:28:33Z change (`44938330`) only pinned each required check to
`integration_id: 15368` (the GitHub Actions app), which prevents a non-Actions
source from satisfying a check by name. Enforcement was `active` and
`bypass_actors` empty in both versions, so no bypass path existed at merge time.

### Round-6 cross-compile artifact smoke

CI's `Build (…)` jobs compile both targets but neither uploads nor executes the
result, so gate 2 is evidenced locally against the exact merged tree.

Both targets built from the merged tree at `cffed52`:

| Build | Command | Exit |
|---|---|---|
| native | `cargo build --release --target x86_64-unknown-linux-gnu --workspace` | 0 |
| cross | `cargo build --release --target aarch64-unknown-linux-gnu --workspace` | 0 |

Artifact identity (`file` + `sha256sum`) — every binary is a valid ELF for the
target architecture, and the cross-built set is genuinely `ARM aarch64`, not a
silently-native fallback:

| Target | Binary | ELF arch | SHA-256 |
|---|---|---|---|
| x86_64 | `disk` | `x86-64` | `2ca7e27794e40867e307906c40f0a6364ea19b8329bd0952f0519464a748b050` |
| x86_64 | `disk-arcana-server` | `x86-64` | `5d0ec9fd0cb230fad47f867364d4c9cdc3b2a69d09ee56b4ac3bb57c8bd4e758` |
| x86_64 | `disk-arcana-client` | `x86-64` | `528f094a6de73a11ee0a40a31d3b906add4ac5b5353af32a1edfa03679818784` |
| aarch64 | `disk` | `ARM aarch64` | `448801ee42c3d5765c34a69320ae98f21ad950a18f9dce784656c0bce522caac` |
| aarch64 | `disk-arcana-server` | `ARM aarch64` | `e0ff04a154b2abc5f05c299f8d1b0dd1f82c6e718c5ad9918093e9bc04a8204b` |
| aarch64 | `disk-arcana-client` | `ARM aarch64` | `632b77ee16d79b44ad9321a7c25f7b521c9ddca400a8206caaeb884beed495e8` |

Native execution smoke (x86_64 only — this host cannot execute aarch64):

| Binary | Result |
|---|---|
| `disk --version` | `disk 0.1.0`, exit 0 |
| `disk-arcana-client --version` | `disk-arcana-client v0.1.0 (Phase 3 gRPC)`, exit 0 |
| `disk-arcana-server` | executes; reaches its own config validation and exits 1 with `missing required env var: DISK_DB_PATH` / `DISK_SYNC_ROOT` |

The `disk-arcana-server` line is reported as-is rather than dressed up as a pass.
That binary parses no CLI arguments — it is env-configured and supervisor-launched,
so `--version` is not a supported flag and it proceeds straight to loading
`ServerConfig` from the environment. Reaching its own structured config error
still proves what an artifact smoke needs to prove: the ELF loads, the dynamic
linker resolves, `main` runs, and the failure is application logic rather than a
broken or mis-targeted binary. Its exit 1 is correct behaviour for an unset
environment, not a defect, and it is unrelated to this lane — the server binary
behaved identically before it.

**Stated limit.** The aarch64 binaries are verified by ELF-header identity only.
No aarch64 host was available, so they were not executed. This is recorded as a
limit of the evidence, not claimed as execution.

### Fresh local gates (round 6, against merged `main` `cffed52`)

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo test -p disk-client watcher` | 22 passed, 0 failed (21 lib + 1 `it_watcher_debounce`) |
| `cargo test -p disk-server share_index --lib` | 22 passed, 0 failed |
| `cargo test -p disk-server --test share_index_watcher` | 5 passed, 0 failed |
| `cargo test -p disk-server --test it_main_boot_wiring` | 4 passed, 0 failed |
| `cargo test --workspace --all-features` | 903 passed, 0 failed, 4 ignored |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | exit 0 |
| `cargo build --workspace --release` | exit 0 |
| `git diff --check` | exit 0 (no whitespace errors) |
| `gitleaks detect` over `41cc2c44..cffed52` | 3 commits scanned, no leaks found |

The four ignored tests are the pre-existing `load_scan` (2), `load_sync_round_trip`
(1) and a `vclock_concurrent_writes` case (1) — all ignored before this lane and
unrelated to it.

### Final hashes

| Artefact | SHA-256 |
|---|---|
| Merged product/test diff, `41cc2c44` → `cffed52`, `crates/` only (6 files, 2454 insertions, 95 deletions) | `b6a4f6b5c684b3452e769cbe674c91cb0785c0d7785c3a4d237de28ce84fa5dc` |
| Full merged diff `41cc2c44` → `cffed52` (7 files, incl. this report) | `d1224030eba0e6e4d2b2206963bbf8707542818295cd40a6d585a12967774c4f` |

Both are reproducible with `git diff <base> <merge> [-- crates/] | sha256sum`.
Consistent with rounds 3–4, this report embeds no self-referential SHA; its
identity is its Git blob hash via `git hash-object`.

The round-4 identity block above records 2433 insertions / 90 deletions, which
was accurate for the round-4 candidate. The merged total is 2454 / 95; the
difference is commits `2529c08` and `ac0e05d`, which landed after round 4.

### What round 6 does NOT close

- **The dependency security gate remains open and is not this lane's to close.**
  `RUSTSEC-2026-0194` / `RUSTSEC-2026-0195` (`quick-xml` 0.39.4), unmaintained
  `ttf-parser` 0.25.1 (`RUSTSEC-2026-0192`) and yanked `spin` 0.9.8 all still
  reproduce on the unchanged base and are owned by `DISK-0066` / `R6-17`, which
  is in flight as pull request 128 (open and iterating as of 2026-07-31; its
  check state is deliberately not pinned here, since it moves). Merging
  DISK-0065 neither fixed nor suppressed these findings, and closing them is
  DISK-0066's exit criterion, not this report's.
- **CI's dependency gate is narrower than a full local audit, which is why
  `Lint` is green on `cffed52` while § Security-gate finding above says the
  dependency gate is not green.** Both statements are correct; they measure
  different things. Reproduced on the merged tree with `cargo-audit 0.22.2`:

  | Command | Exit | Reports |
  |---|---|---|
  | `cargo audit` | **1** | `RUSTSEC-2026-0194`, `RUSTSEC-2026-0195` as vulnerabilities (7.5 high); `ttf-parser` unmaintained + `spin` yanked as warnings |
  | `cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195` (the exact CI form) | **0** | yanked `spin` warning only |

  Two separate narrowings produce that difference:

  1. **The `quick-xml` suppressions live only in CI's command line.** The
     rationale is written up in the repo-root `.audit.toml`, but cargo-audit does
     not read that file — it reads `.cargo/audit.toml`, which lists only
     `RUSTSEC-2023-0071`. Proof: in the plain run above `RUSTSEC-2023-0071` is
     absent (suppressed by `.cargo/audit.toml`) while `0194`/`0195` are present
     despite being listed in `.audit.toml`. So the root `.audit.toml` entries for
     `0194`/`0195` are **inert documentation**, and the only thing actually
     suppressing them is the `--ignore` flags in `ci.yml`. A developer running
     `cargo audit` locally gets exit 1.
  2. **The deny step runs `cargo deny check licenses` only** — not `advisories`
     or `bans` — so `RUSTSEC-2026-0192` (unmaintained `ttf-parser`) and yanked
     `spin` 0.9.8 are never evaluated in CI at all. The job name
     "Lint (fmt + clippy + audit + deny)" overstates that step's coverage.

  The underlying `quick-xml` argument is sound (build-time-only dep of
  `wayland-scanner`, parsing the trusted fixed Wayland protocol XML shipped
  in-crate, never runtime or user input), so these are scoped and argued
  suppressions rather than silent ones. The defect is in where they are recorded,
  not in the reasoning. The operational consequence stands: **a green `Lint` must
  not be read as "no outstanding advisories".** Recorded as an observation for
  `DISK-0066` / `R6-17`, which owns the remediation; DISK-0065 changes no
  dependency and no gate configuration, and this report does not alter either.
- **Windows service / full-VM e2e** remains operator-gated per DISK-RB-008; no
  Windows VM sync cycle was run in this lane.
- **aarch64 runtime behaviour.** The aarch64 artifacts are verified by ELF-header
  identity only; no aarch64 host was available to execute them.

## Non-claims

This report does not claim epic completion. `DISK-0065`'s own five numbered
proof areas, the six lettered A–F rereview corrections, and the four deployment
gates are closed; ARCA-0194 `R6-14` and the `DISK-0066` dependency lane are
tracked separately and are not closed here.

Superseded earlier non-claims, retained for audit trail: rounds 3–5 stated that
the historical Windows failure log was unavailable and that "earlier Windows
causality remains UNKNOWN". Round 6 retrieved the log and proved the cause — see
§ Round-6 closure → Windows causality. The narrower non-claim that survives is
that no statement is made about any Windows failure predating run `30359528906`,
whose logs have expired.

## Deployment gates (closed — round 6)

All four gates named in earlier rounds — Windows CI re-run, cross-compile
artifact smoke, ruleset readback against the exact main merge base, and exact
merged-main CI proof — passed and are evidenced individually in
§ Round-6 closure → Deployment gate closure. The condition recorded in earlier
rounds was: all four gates pass → merge; any gate fails → root-cause and
re-verify. All four passed, and the branch was merged as `cffed52`.
