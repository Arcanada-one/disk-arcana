# Explicit full verification groups

`.arcana/verify.json` declares executable `full_test` commands for the repository,
all eight Cargo members, and the detached fuzz package. `scripts/full-test-group.py`
executes source commands; it accepts neither logs nor cached verdicts. Invoke a
command from its declared group directory, with dependencies already installed.
Python 3.11+, the selected Rust toolchain, native C/linker/protoc, and the plugin's
locked npm installation are prerequisites. Set a task-owned `TMPDIR` and Cargo
target directory. The root composition invokes `test-obsidian-integration.sh`, which runs `npm ci`
(including the package's installation lifecycle scripts) and Cargo build/run.
Cargo invocations use `--locked`; registry/cache downloads can still occur.
Every runner child command checks the workspace, fuzz and plugin lockfile bytes
before/after execution. Mutation cannot yield success; failed-command output is
retained. This is not an offline or zero-installation workflow.

Each Cargo group runs the **entire package** in no-default-feature and all-feature
configurations, including ignored tests and doctests. It does not select individual
tests. A positive count is required, and remaining ignored tests are unmeasured.
This is host-platform evidence, not proof for other operating systems.

The root group composes every Cargo group, Python tests and metadata self-test,
all Linux deployment test scripts, strict plugin/tool compiler projects, all
plugin tests and its daemon integration, the complete load harness, and all fuzz
targets. The fuzz group discovers every target from its Cargo manifest and runs
600 seconds each, matching the repository's deep campaign. A short smoke run does
not discharge that declaration. Root and per-package checks are distinct graph
obligations; no command prints a cached success to avoid executing them.

A complete storage run includes the existing ignored B2/R2 roundtrip tests. They
write/delete sandbox objects. An independently authorized disposable sandbox is
required, and `DISK_FULL_TEST_REMOTE_SANDBOX=authorized` is an explicit opt-in,
**not an authority grant**. Without it the runner exits 127 before provider calls.
Personal/root groups similarly return 127 when required Linux `openat2` cannot
execute. Missing executables, empty suites and skipped tests are not measured;
nonzero test exits remain failures. Root checks these prerequisites before broad
execution. Production use and real personal data are not authorized by this profile.

Compiler membership is explicit. The ordinary Obsidian project keeps strictness
and checks `esbuild.config.mjs` and `vitest.config.ts`; the scripts project checks
`verify-personal-capture-vectors.mjs`. `tsconfig.generated.json` applies the same
strict settings to the checked-in generated `main.js`. It currently reports real
compiler diagnostics rather than hiding the bundle with `checkJs:false`, changing
strictness, or modifying emitted output. Program owns generated-artifact instrument
semantics. This declaration is not a claim that every measurement passes.

These declarations apply to the new candidate revision. They do not retroactively
admit PR238/PR239 or replace their immutable receipts. Existing CI success, skipped
coverage, local ENOSYS and source review remain separate evidence. Resulting-main,
independent review, full graph admission and runtime authority require their own
receipts.

Unittest discovery is accounted from its stderr summary: zero execution and any
unexecuted skips remain unmeasured. Plugin accounting uses fresh JSON assertion
inventories, not a human-readable passed counter. Only skipped cases in
`test/daemon-integration.test.ts` can be deferred, and the subsequent real daemon
integration must pass exactly those file/full-name identities. Other skips,
pending/todo cases, duplicate identities and inconsistent totals cannot be hidden
by positive cases. Existing daemon/filesystem/SQLite postconditions remain intact.

## Runner configuration and bounded canaries

`scripts/full-test.env.example` declares the runner inputs and is registered in
`.arcana/verify.json`. It is documentation, not an authorization file or an
implicitly loaded environment. In particular, setting the remote sandbox flag
never grants permission to access a provider.

A process canary may execute a complete small group (for example `disk-proto`,
both feature modes) and refusal controls on an exact committed source. That
measures runner behavior only; it does not admit the repository-wide group or
transfer an older change-admission receipt. Keep its plan, original source
binding and result together, and submit them to the canonical Program verifier.

The offline Rust-isolation fixtures normalize only metadata of external host
ancestors outside their temporary tree. Fixture file and directory permissions
remain real; explicit writable-parent and foreign-owner arms verify refusal.
Unexpected bootstrap is blocked, while bootstrap tests mock all subprocesses.
This is fixture isolation, not a relaxation of the production path checks.
