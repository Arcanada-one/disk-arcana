# Explicit two-realm synthetic capture worker

PERSIST02-TWO-REALM-WORKER, task413ae7dd-1ef6-42db-a88f-2829f3c7359a.
The feature-gated binary accepts exactly:

    disk-capture-fixture-worker seed|read|denied ROOT REALM_UUID DEPLOYMENT_UUID a|b

Both identifiers are explicit canonical lowercase non-nil UUIDs. Deployment is a
synthetic provider allocation identity, not Auth deployment_generation or an
operation ID. The encrypted fixture manifest must declare its own deployment ID;
this CLI does not infer it from another field. Selector a is fixed abc, b fixed
xyz (equal-length, distinct bytes). Arbitrary personal payloads are not accepted.

Historical three-argument behavior is removed from this candidate. Older receipts
remain bound to their original source and hard-coded realm; they prove no second
realm. The canonical capture fixture's realm, part digest, size and fingerprint
are regenerated, then verified through actual CaptureDescriptor::parse. Request
and descriptor bindings use the same values. Allocated object/revision IDs remain
the same across realms intentionally to exercise isolation.

Seed initializes and stages. Read first reads already-existing exact bytes before
requesting the original idempotent stage receipt; it cannot silently repair a
missing or different capture. New processes reopen and return the same receipt.
Wrong realm/deployment/selector fails, with no successful stdout. Denied validates
the unavailable startup boundary and prints STARTUP_UNAVAILABLE without creating
storage. This is not real Auth authority or encrypted-mount admission.
