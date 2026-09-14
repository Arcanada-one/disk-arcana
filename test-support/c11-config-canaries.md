# C11 CLI configuration reader canaries

This slice calls the actual private `api_base` and `bearer_token` helpers in
agents, org, selective-sync, sharing, snapshots, trash and versions. Each owning
module has a cfg(test,Linux) child test that passes those exact functions to a
single CLI test driver. No production function, visibility, dependency or HTTP
behavior changes. The shared environment helper is declared once at CLI test
root, avoiding duplicate modules within one compilation.

The15 shared fixture definitions run independently for every reader:105 distinct
reader/case IDs. They cover defaults, env overrides, explicit-argument precedence,
trailing slash trimming, empty values, and preserved whitespace. A separate
negative control supplies a wrong token expectation and requires the actual
`configuration field token` assertion diagnostic; a timeout or zero selected test
cannot satisfy it. A child
without its envelope is a dispatch entry, not passing canary evidence by itself.

Every child receives an empty environment followed by explicit synthetic fixture
values. It calls only the two pure helper functions. The strings are never used
for network requests or authentication. Empty/whitespace base and whitespace token
acceptance are existing behavior being measured, not approved deployment policy.
The override arguments travel in the test-control envelope and are removed before
comparing the expected result fields. No parser/validator is copied.

Run on the exact task-owned Linux DEVS candidate with its pinned Rust toolchain:

```sh
cargo test -p disk-cli --bin disk --locked c11_ -- --nocapture
```

Record the emitted `CONFIG_PROBE_CASE_OK C11-<reader>-<case>` IDs, test counts,
exact source/tool/binary hashes, command result and cleanup in external canary
evidence. Do not reuse the earlier C01/C03/C04 fixture count. The map in
`c11-config-canary-map.json` enumerates every expected reader/case association.
Definitions and local formatting do not constitute executed canaries; runtime
remains NOT_MEASURED until the DEVS receipt supplies actual results.

C02 and C05–C10/C12–C14 remain pending. This slice does not demonstrate HTTP
contract conformance, live deployment, real authorization or personal storage.
