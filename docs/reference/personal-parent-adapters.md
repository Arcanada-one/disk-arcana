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
