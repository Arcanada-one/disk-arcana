# Synthetic provider reference

Status: nondeployed persistence foundation. Authorization and private-data
admission are unavailable. The internal SQLite schema is not a shared wire
contract. This reference contains no production setup procedure.

## Boundaries

Use freshly created task-owned synthetic roots with no concurrent untrusted
same-UID or privileged filesystem mutator. Absolute root names start with
`disk-personal-fixture-`; this is a misuse guard, never authority. Root/storage
directories require mode 0700, current UID and matching device. DB/WAL/SHM/rollback
journal/lock/marker entries require regular files, mode 0600, one link, current
UID and the same device. Checks precede SQLite opens and repeat before use.
Retained root/directory identity rejects substitution. Blob operations use
Linux directory handles and openat2 restrictions; publication uses no-replace
rename without overwrite fallback.

SQLx opens SQLite by pathname inside this exclusive root. These checks do not
constitute a secure VFS, hostile-host protection, encryption or authorization
before private access. SQLite housekeeping can write WAL/SHM during logical
inspection. Inspection does not mutate/promote blobs or provider states;
integrity failure can persist a poison marker. It is not zero filesystem IO.

The writer lock is local serialization only. Its guard is armed before the first
DB-open await and released only after SQLx acknowledges successful shutdown.
Abandonment, panic, initialization/open/close cancellation or uncertain shutdown
retains its descriptor until process exit. Further opens/operations in that
process fail closed. Each disposable worker accepts one command/one root, so it
cannot loop through unbounded abandoned roots. Do not reuse an abandoned process.
No async-Drop/background shutdown assumption or Auth fence is claimed.

## Local states

One operation reserves one immutable allocation/attempt as PREPARED. Operation,
attempt, object/revision, kind, length and digest cannot change. Identical retry
returns stable evidence; changed identity or object/attempt collision conflicts.
An untracked file cannot acquire a reservation and later be adopted as provenance.

Stage creates an exclusive file, checks exact length/SHA-256/note UTF-8, syncs the
file, renames without replacement and syncs both directories/new ancestors.
Only then can one SQLite transaction change PREPARED to DURABLE and persist local
evidence. A filename, complete blob, lost response or timeout does not prove commit.

Incomplete staging is retained as UnresolvedPrepared: no truncation, unlink or
guessed resume. This minimal behavior does not promise progress for partial
attempts. Explicit fresh synthetic stage may continue only the identical complete
verified recorded staging/final file, repeating required syncs. Inspection cannot
promote it. Orphans stay untouched. There is no cleanup/deletion API.

Startup checks the bounded durable inventory against actual bytes. Missing or
corrupt durable data poisons the whole provider, including unrelated writes.
A one-way POISON marker is synced; uncertain persistence keeps the instance
unavailable and startup still rediscovers the corrupt record. No reset/repair
API exists. Retain evidence, then remove only the entire owned disposable root.
This synthetic scan is not a future Auth-authorized startup scan.

## Limits and dependencies

The provider permits 128 attempts and 64 MiB of declared reserved bytes. Notes
are at most 65,536 bytes, attachments 1,048,576 bytes. Writes use bounded chunks;
verified reads use at most one blob plus one rejection byte. Worker JSON is capped
at twice the blob maximum plus 8192 bytes; hexadecimal body size is independently
capped. Each metadata record is limited to 2048 bytes.

Required table/trigger definitions match the embedded migration and the complete
schema object set is allowlisted, including its five unique indexes. The only
optional trigger is the exact reject-only synthetic SQL fault fixture; arbitrary
extra triggers or same-name mutations fail schema admission.

Connections select/read back WAL, synchronous FULL, foreign keys ON, trusted
schema OFF, temp_store MEMORY and a suggested 2048 KiB page cache. MEMORY controls
location, not total RSS. Actual resource budgets and host durability need separate
measurement. No environment-selected database URI or in-memory fallback exists.

The crate targets Rust 1.97.1, without claiming the workspace's older inherited
MSRV. SQLx 0.8.6 selects bundled SQLite; locked libsqlite3-sys 0.30.1 compiles its
packaged C source/bindings. System SQLite headers, another driver and global
installation are not required by this feature selection. Actual features/build/
advisories still require verification; bundled does not imply encryption.

## Verification

The [scoped script](../../scripts/test-personal-provider.sh) takes explicit task
Cargo/rustc paths and a task-owned target. It checks features, formatting, clippy
and real file/SQLite tests. The surrounding runner separately checks actual
default/all-feature production binaries with syscall tracing for private-root
opens and binds. The unit production test proves refusal/no mutation only.

Crash tests wait for explicit child checkpoints, kill only that child and query
through a new process. before_commit and after_commit are outside COMMIT; no
mid-COMMIT, power-loss or media-durability claim follows. IO injections test error
handling. A real SQL trigger rejects the final inventory transition and proves
rollback. An actual paused SQLite VM callback tests abandoned/cancelled worker
lock retention and second-process denial until the owning process exits.

An actual foreign-device negative requires a task-owned mount namespace and
recorded device IDs. Symlink denial is a distinct result. Verify release inventory
excludes the fixture executable. Cargo.lock changes need whole-workspace graph/CI
disposition even when third-party package versions are unchanged.

Authorization, cross-person denial, shared receipt/outcome registration,
publication/cancellation, cleanup, TLS/exporters, release admission, lifecycle
fences, encrypted realm provisioning, capacity and deployment remain separate
implementation and verification obligations.
