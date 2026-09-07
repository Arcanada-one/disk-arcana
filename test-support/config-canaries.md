# Synthetic configuration reader canaries

This first slice covers C01 (ServerConfig), C03 (S3 config constructors), and C04
(telemetry and billing default-tier env readers). It is test-only. It does not
start a service, create a database, access a cloud provider, or authenticate a user.

Each matrix case launches the same exact test executable with `--exact` and an
empty environment. Only checked synthetic fixture values and the expected field
projection are installed. No real credentials or inherited endpoint values reach
the child. A10-second deadline bounds each child. The parent requires a reader
completion marker and one passing child test; zero selected tests cannot pass.
The server integration target also checks that zero-selected-child tests and a
wrong expected field are rejected. Only the matrix cases and explicit verifier
negative controls, not uninvoked child entry tests, count as canary evidence.
Run with `--nocapture` to retain each `CONFIG_PROBE_CASE_OK <id>` association.

Server and storage integration tests call their public constructors. Telemetry
and billing tests are cfg(test,Linux) children of the actual private module, so
production visibility and dependency architecture remain unchanged. There is no
copied parser or alternate validator. `config-canary-map.json` binds fixture IDs,
keys and readers. Default URLs are compared as strings only, never contacted.
The `/synthetic/config-probe` path literals are returned by the config parser;
these tests do not open or create those paths.

Execute on the task-owned Linux DEVS checkout using the selected Rust toolchain:

```sh
cargo test -p disk-server --test config_environment_canary --locked -- --nocapture
cargo test -p disk-storage --test config_environment_canary --locked -- --nocapture
cargo test -p disk-server --lib c04_ --locked -- --nocapture
```

No Cargo manifest, lockfile, provider implementation, release target, CI workflow
or service entry changes are part of this slice. The normal source compilation
must still pass on DEVS; local formatting is not execution evidence. The verifier
operator records exact commit/tool hashes, commands, case counts and source/entity
associations in the external canary receipt. All groups outside C01/C03/C04 remain
pending; these tests do not close the complete inherited config impact set.

These are observations of existing reader behavior, not stricter product policy.
Examples intentionally assert zero TTL acceptance, invalid/overflow numeric
fallback, empty S3 strings, and duplicate share-root last-wins. They do not assert
such values are safe to deploy. Invalid credentials/URLs are not sent anywhere.
OAuth/JWT settings are parsed only; no Auth or personal-service conformance follows.
The derived missing-JWKS error branch is unreachable for valid current JWT modes
because those modes supply a default issuer; it is not claimed as executed.
