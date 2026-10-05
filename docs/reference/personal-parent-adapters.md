# Disabled personal parent adapters

This is PERSIST-02 source integration, separate from the PERSIST-02F synthetic
foundation. `disk-arcana-personal` still unconditionally exits 78. No router,
issuer, encrypted mount, storage adapter, release path or runtime is registered.

## Source contracts

The source design is Atlas `INTEGRATION-SOURCE-SPEC-v0.5.md`, SHA256
`b11298e74a8c941abf50a73c48f2f115bf70bb8a4cfc3b76e28414f897b9c13d`,
qualified by the original proposed `disk-wire-closure/1-proposed` package in
Program `integrations/arganize-me/personal-owner/disk-contract/`. These are
proposed integration semantics, not deployed protocol acceptance or authority.
Shared `personal-capture/v1` remains the descriptor/receipt authority; reuse the
existing `CaptureDescriptor` parser and fingerprint instead of allocating IDs.

`parent_wire::ReferenceRequest` decodes the exact closed four-field reference
record with the existing 4096-byte bound. It has no realm/resource override.
Its error encoder emits only the native fixed vocabulary and request identity;
it never emits an underlying error, realm, body, receipt or authority value.
Duplicate fields, unknown keys and wrong versions refuse. Errors conservatively
set retryable=false; an uncertain write requires exact reconciliation.

`CaptureDescriptor::verify_receipt_bytes` binds all Shared ObjectReceipt fields
to the complete parsed descriptor and verifies actual UTF-8 bytes, length and
SHA-256. This is the structural/byte half of trusted readback only. Authenticated
Disk lineage, original attempt, live access and native outcome association must
also be verified by the real authority port. A caller's receipt cannot authorize
this operation. A local synthetic commit is never converted to a wire receipt.

## Parent orchestration

`parent_adapter::Parent` composes trusted in-process `Authority` and `Storage`
ports. `Contract` associated types preserve the exact native deployment,
configuration-reference, request, receipt and outcome types supplied by their
owners. They are not newly invented public JSON or an HTTP endpoint. There is
no caller-selected implementation registry or boolean admission constructor.
The default `UnavailableAuthority` cannot construct its uninhabited handles and
refuses before any callback. Tests define fake implementations only in cfg(test).

Startup validation must authenticate deployment/executable/configuration,
realm/account and dedicated encrypted mount/key domain before invoking the
callback. The authority port then validates the exact Auth capability and holds
revocation exclusion and the common capture generation fence until the complete
operation, durable commit and registration callback have settled. Ports are
synchronous: returning after merely scheduling an asynchronous commit violates
the interface. A synchronous future adapter must await completion internally;
this module neither blocks a live async executor nor implements that transport.

The write path observes the original attempt before hydrating a body. An unseen
state is usable only for an authenticated fresh allocation with no unresolved
prior effect. PREPARED and unknown return pending without re-staging; corrupt
state refuses. A durable retry validates the submitted body, then verifies its native receipt and actual bytes,
then registers/reconciles the same original outcome without allocating new IDs.
Lost registration acknowledgment remains pending. The storage port must enforce
exact descriptor bounds before reading/writing, immutable retry identity, and
atomic durable inventory/journal semantics. The generic maximum after hydration
is an extra guard, not a substitute for bounded streaming by the input adapter.

Readback verifies producer provenance and actual bytes under the same live
context. Results are internal observations, not permission to send private data
on a network. Auth release leases and native SDW1 framing remain an unregistered
transport seam; no private output is automatically released by this module.

Product owns publication and terminal cancellation CAS. Disk MUST NOT emit
`product_committed` or `product_cancelled`. Cleanup first authenticates the
registered Product cancelled outcome and exact object set under the shared fence,
then observes inventory, durably tombstones, unlinks only that set, syncs and
journals `disk_cleaned`. Unknown/PREPARED never authorizes cleanup. Tombstone
failure cannot reach unlink; incomplete cleanup remains pending. A cleaned retry
retains its original outcome. Native historical receipts must survive deletion.

## Remaining implementation seams and validation limits

No production storage implementation is supplied: foundation02F's pathname
SQLite under exclusive synthetic ownership is not a secure production VFS.
Actual deployment/mount verifier, Auth client/lease lifetime implementation,
native outcome codec and durable journal adapter, positive fenced absence,
release transport and CAB proof issuance remain owner integration seams. This
batch implements orchestration and structural/byte validation, not those effects.
Do not call this full PERSIST-02 completion or infer an account/storage grant.

Unit controls check denial ordering, guard lifetime, altered bindings/bodies,
uncertain commit and lost acknowledgments, terminal exclusion and tombstone-before-
unlink using fake ports. Recreating a service over retained fake state tests
adapter reconciliation choices, not SQLite/process-crash durability. Existing
02F crash tests retain their separate meaning. No new live-storage or private
artifact execution is authorized. One validation cycle follows the complete
source batch; canonical graph/CI/independent review remain integration gates.

CAB confirmed current `TrustedDiskVerifier.verifyExactReadback({descriptor,
receipts, call}): Promise<void>` at Data `e613`, `src/integration.ts` in message
`msg_8638446b8752`. `call` is server-only realmId/opaque authorizationHandle,
never an HTTP grant. `verify_receipt_set` checks complete descriptor membership
and duplicate parts, as well as each exact body. The authenticated producer
transport must bind native receipt/outcome/attempt provenance and live access
before returning CAB proof. Product retains terminal publication/cancellation.

## Concrete native binding (successor to e9b82)

`parent_native::NativeContract` now supplies concrete deployment selection,
protected references, parsed capture request, ObjectReceipt and native Disk
owner-outcome types for `Parent`. `Outcome` admits only the existing
`disk_stored` and `disk_cleaned` closed records. IDs and decimal-string u64
counters reject coercion/overflow; native registration JSON round-trips the
producer fixtures. JSON encoding is not JCS/signature issuance. No Product
committed/cancelled outcome can be parsed as a Disk outcome. Nothing constructs
these outcomes from synthetic `LocalCommit`.

`parent_authority::NativeAuthority` implements the parent Authority interface.
Its `Control` transport callback supplies actual provisioner/Auth observations
while holding the corresponding nonserializable native leases. The adapter
compares complete deployment/config/executable/key-domain selection, realm,
operation, full descriptor identity and selected part before entering storage.
The private Startup/Effect wrappers cannot be constructed, cloned or deserialized
by request handlers. A structurally parsed selector is never a live wrapper.
`Control` must perform real authenticated observation and retain revocation
exclusion; a caller-provided implementation or cached boolean is not supported.
The two internal identity strings are exact comparison keys, NOT replacements
for the Shared requestFingerprint or Auth request-signing canonicalization.

Native durable verification binds all original owner receipt, participant,
process/deployment generation, operation, capture, owner commit, sequence,
resource-binding digest and storage receipt identity to authenticated original
Auth readback. Current process generation must not replace historical lineage.
A lost registration remains pending. Registration cannot submit a Product
terminal outcome or a stored outcome under a cleanup operation.

`parent_native::NativeStorage` is the concrete parent Storage adapter. Its
NativeBackend supplies admitted handle-relative VFS/native-journal operations,
not caller-provided callbacks. The adapter checks the body before mutation,
checks returned Disk outcome against the selected native object, and performs
actual SHA256/length/UTF8 readback over bounded backend bytes before success.
This is a new implementation layer, not a type alias or a synthetic provider
cast. Backend observation is still required to distinguish positively new work
from unknown prior work; the adapter never invents no-commit evidence.

Cleanup decodes the exact native cancelled resource, checks descriptor realm,
capture, fingerprint, terminal revision, cancellation generation+1 and complete
part membership. It derives the allowed object/revision set from the original
descriptor, never from a caller path or prefix. It passes only that set to the
backend, validates the returned disk_cleaned object set and Product outcome
reference, then authenticates original effect lineage before registration.
Tombstone-before-unlink ordering remains in Parent under the common lease.

The native fixture file contains selected unchanged values from Program's
hash-pinned wire-closure fixtures and records the source SHA256. Tests exercise
these concrete adapters, not a replacement invented wire protocol. Fake leaf
Control/NativeBackend implementations prove field checks and invocation order;
they do not attest live authentication, encrypted storage, durable journals or
concurrent revocation. Real deployment-specific Control and NativeBackend
implementations remain unregistered and absent. The production binary still
exits78. Implementing those providers must preserve the admitted handle/lease
contracts; merely instantiating a struct or copying fixture values cannot enable
production. This does not claim complete parent/runtime delivery.

## Descriptor-relative native journal primitive

`parent_journal` performs actual Linux IO over an already supplied directory
handle. It is a reusable storage prerequisite, not a SQLite VFS, NativeBackend
implementation, encrypted-mount verifier or runtime admission constructor.
The trusted provisioner must supply an existing0700 current-UID directory with
matching device/inode and existing0600 single-link writer.lock. There is no
pathname constructor, root creation, missing-mount fallback or storage scan
before the caller's admission. The caller must retain startup/access/effect
permission and exclusive ownership excluding untrusted same-UID/host mutation.
Descriptor checks cannot protect against a privileged hostile host.

All entries use openat2 with BENEATH, NO_SYMLINKS and NO_XDEV. Unsupported syscalls
return their original IO error; there is no weaker openat fallback. File checks
require regular0600 current-owner single-link same-device entries. Reads are
bounded to16384 bytes and metadata changes during read refuse. Each scan opens a
fresh directory description to avoid sharing an exhausted directory cursor.

The source-local record format `disk-local-owner-journal/1-source` contains the
original effect lease and unchanged native Disk owner outcome. This is an
internal disk format, not a new public wire record or Auth OutcomeRecord. The
journal limits retained records to128, enforces unique effect lease, owner
receipt and local sequence, and compares exact original lineage before write.
A record is written exclusively to its lease's pending file, file-synced, renamed
without replacement and directory-synced. Partial/pending/corrupt entries never
auto-promote or get truncated/unlinked. Matching retained bytes return Existing,
which is an observation, not proof that an earlier unknown call completed.
Missing entries never prove no-commit. No cleanup, reset, prune or broad deletion
API is provided. Tests remove only their newly created disposable fixture roots.

Writer serialization uses an existing file and nonblocking flock. Explicit
unlock releases the shared open-file description when synchronous IO has
returned, including after a concurrent fork. This does not weaken the separate
02F SQLx abandoned-worker descriptor-retention contract. No async IO, SQL worker,
background commit or thread cancellation is introduced by this primitive.

A journal-only fsync is not atomic object+inventory+Auth completion. The remaining
Disk-owned integration is a safe production inventory/VFS and native backend
transaction protocol that composes object durability, this local record and
Auth reconciliation without changing native receipt meanings. Do not wire the
primitive straight to Parent::Committed or cast synthetic02F as that provider.
Auth Disk resolve/access/effect/outcome producer transport remains with the
existing Auth/CAB source owner; Data first-intent/recovery is not that protocol.
Infra operational discovery found no maintained admitted provisioner/verified
directory-handle source reference in its existing scope. The missing source
binding remains a PERSIST integration obligation; no provisioner custody owner
has been identified. Neither source dependency is a request for credentials,
mount activation or live effects. Production main/startup remain denied.

## Descriptor-relative file IO and native inventory readback

`parent_vfs::Directory` supplies synchronous file operations anchored to an
already admitted directory FD, with closed inventory, rollback and exact native
object names. Existing files require same-device, current-owner, single-link,
regular0600 metadata; the directory requires0700 and the expected inode.
Every open uses openat2 confinement, with no syscall or path fallback. A scoped
exclusive writer lock retains all page-file handles through the callback. File
sizes and positional IO are bounded; short reads zero-fill but return the actual
byte count, so a future SQLite adapter must report short IO rather than success.
New objects are exclusive creations, never opened for overwrite. Write/sync or
uncertain creation errors poison this Directory instance across callbacks;
there is no reset method. Recovery requires a separately admitted recovery path.
No removal, truncation, shared-memory or mmap shortcut is supplied.

This is the file-IO portion of a VFS, NOT a registered SQLite VFS. In particular,
it does not implement the SQLite ABI, rollback recovery/commit/delete protocol,
WAL, database locking levels, or the complete NativeBackend transaction. These
remain Disk-owned source obligations, not a request for runtime permission and
not silently reassigned to Infra. A future ABI binding must map short reads and
IO errors correctly and preserve the scoped lock/uncertainty contract. Existing
SQLx pathname access is not substituted for that binding.

`parent_inventory::verify_original_readback` connects actual native journal
inspection with actual confined object reads. It requires a unique unchanged
original-effect match, exact selected receipt, bounded length and hash/body
validation. Missing or ambiguous journal records remain Pending; they never
establish fresh/no-commit. The result exposes only the original outcome, not
private bytes or a release capability. The caller must retain an authentic
capture/access fence and supply independently authenticated original lineage.
The result is a consistency check, not durable transaction or Auth admission.
No NativeBackend::Committed result is manufactured from this readback helper.

The local environment returns ENOSYS for openat2 independently of Rustix, as
measured with a bounded read-only libc syscall probe. The reported Linux6.8
release supports the upstream interface introduced in5.6, but active seccomp
filters can return errno without executing a syscall. The specific filter or
host implementation responsible is not established by the probe. Local real
filesystem checks remain unavailable; their failing logs are retained. Do not
change confinement or turn environment refusal into passing tests.

Primary interface references: [Linux openat2](https://man7.org/linux/man-pages/man2/openat2.2.html),
[Linux seccomp filters](https://kernel.org/doc/html/latest/userspace-api/seccomp_filter.html),
and [SQLite file methods](https://sqlite.org/c3ref/io_methods.html).
These describe API semantics; they do not attest the current sandbox filter or
provide a deployment/runtime grant.
