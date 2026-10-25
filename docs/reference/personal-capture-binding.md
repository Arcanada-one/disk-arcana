# Personal capture binding: synthetic v2 provider profile

Task: PERSIST02-CAPTURE-BINDING (`c3de996b-3af5-4973-9803-e7884e5b8998`).

This bounded consumer implements the existing Shared `personal-capture/v1`
descriptor, fingerprint input and full retry identity. Source of truth is
`arcanada-shared` commit `b4f4430365710b215740b1482645467d7d622a70`,
`packages/access-contracts/src/personal-capture.ts`. The Rust consumer exists
because the provider cannot import a TypeScript runtime package. Canonical
vectors must be checked against that actual Shared implementation before review.

The validated descriptor is structural data, never Auth authority. It additionally
checks SHA-256 of Shared's canonical fingerprint input. Full retry identity binds
IDs intentionally omitted from that fingerprint. JavaScript safe-number semantics,
nil UUID syntax and text/plain UTF-8 for both parts are preserved; the existing
provider separately rejects unsupported nil allocation IDs. Note and attachment
ceilings are 65,536 and 1,048,576 bytes. The canonical identity's maximum length is
798 ASCII bytes, derived from both full parts and both maximum safe counters.

Capture fixtures require a fresh v2 inventory. Initialization exclusively creates
a new directory, verifies emptiness through its owned file descriptor, and creates
children relative to that descriptor without following symlinks. It refuses any
existing directory. There is no automatic migration or adoption of v1 fixtures.
The legacy fixture API remains v1-only. Both versions retain exact schema checks.

Reservation inserts the existing attempt and its capture binding in one SQLite
transaction before staging bytes. The immutable binding's unique key is
`realm_id, capture_id, part_id, cancellation_generation`. A failed binding insert
rolls back the attempt too. Each existing provider `operation_id` belongs to one
part allocation and must be stable across retries; this is not an Auth operation
ID, lease ID, or an invented correspondence between those protocols. Reusing an
operation requires the entire canonical descriptor and selected part to match.
Reads require the same binding. Missing or orphaned binding rows deny reopening
before durable-body consistency reads. LocalCommit remains local fixture evidence,
not an Auth-admitted outcome or a wire receipt.

The startup handle cannot be constructed or deserialized by callers. Its real
verification function returns unavailable before storage inspection. Only the
explicit `synthetic-fixtures` build supplies a synthetic handle; this is not an
implementation of encrypted-mount verification or trusted deployment admission.
The production binary remains exit 78. No personal routes, network listener,
credentials, real-account admission, encrypted storage, or producer outcome
protocol are enabled here.

Validation must include actual SQLite transactions, two-process reopening,
substitution and collision negatives, and OS-observed absence of storage access
when startup denies. These proofs do not turn synthetic startup into real Auth
or encrypted-mount admission.
