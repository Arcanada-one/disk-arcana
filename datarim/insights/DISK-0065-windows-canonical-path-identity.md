# Insight — filesystem watchers must arm and filter on one path spelling

- Task: `DISK-0065`
- Epic: `ARCA-0194`
- Recorded: 2026-07-31
- Source: direct diagnosis of a recovered Windows CI failure log
  (job `90275566736`, run `30359528906`, 2026-07-28), not external research.

## Finding

A `notify`-based watcher that is **armed** on one spelling of a directory and
**filters incoming events** against a different spelling of the same directory
silently discards every event. There is no error, no warning and no dropped-event
counter — the events simply fail the root-prefix test and are skipped.

In `spawn_share_index_watcher` the backends were registered with the caller's
`share_roots` while the index loop resolved events against `canonical_roots`
(the `std::fs::canonicalize`d form). The fix is one word — arm the backends from
`canonical_roots` — so that registration, the event filter, and `full_reconcile`
all share a single path identity.

## Why it presented as Windows-only

`canonicalize` is where the two spellings diverge, and it diverges by platform:

- **Windows** returns a verbatim (extended-length) path — `\\?\C:\Users\...`.
  The raw path handed in by a caller has no `\\?\` prefix, so
  `event_path.strip_prefix(canonical_root)` never matches. Every event is dropped.
- **Linux/macOS** normally return the same string for an already-absolute,
  symlink-free path, so registration and filter spellings coincide by accident
  and the bug stays latent.

The defect was therefore **cross-platform in the code and Windows-only in its
symptom**. Fixing it on the canonical-root side is a genuine invariant repair,
not a platform-specific workaround.

## Failure signature to recognise

The symptom is a *timeout on an expected index mutation*, never a crash:

```
thread 'share_index_watcher_tombstones_on_delete' panicked at
crates\disk-server\tests\share_index_watcher.rs:103:5:
MetaDb tombstone for gone.txt not written within deadline
```

A watcher test that hangs until its deadline and then reports "not written"
should prompt a path-identity check **before** any timing investigation. The
tempting wrong fixes are all inert here: raising the deadline, adding a sleep,
or marking the test `#[cfg(not(windows))]`. None of them touch the cause, and
the last one hides a real production defect.

## Rule to carry forward

> Canonicalise once, at the boundary, then use only the canonical value.

Do not canonicalise at the point of use. When a subsystem holds both a raw and a
canonical form of the same path, that pair is a latent bug: any code path that
mixes them fails on Windows and passes on Linux. Where a struct must carry both,
name the fields so the difference is impossible to miss (`root` vs
`canonical_root`), and make the watcher-registration site take the canonical one.

## Related

- Merged as `cffed529994e5f11586e13d6dabe6a991537c049` (PR 126), commit
  `ac0e05d` "fix(watcher): unify canonical Windows roots".
- Independent confirmation: unrelated dependabot PR 123 failed the same Windows
  Test step on 2026-07-28 and passed on 2026-07-31 with no change of its own,
  purely by rebasing onto a `main` that contained the fix.
- Full evidence chain: `docs/verification/DISK-0065-local-candidate-2026-07-30.md`
  § Round-6 closure.
