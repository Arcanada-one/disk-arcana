# INFRA-0370 Dedicated Staging Runner Design

Status: DESIGN

## Decision

Provision one small KVM guest on `arcana-agents` for the existing GitHub Actions
runner group `disk-arcana-stage`. The guest is a dedicated test boundary: it
runs no production workload, has outbound-only QEMU user-mode networking, and
exposes its administrative SSH port only on the host loopback interface.

This closes the live test/production symmetry gap without buying capacity,
weakening runner-group restrictions, sharing a runner user, or treating a
queued workflow as evidence.

## Current evidence

- Disk `origin/main` was `5a646bc52767fe9cf9ae2e3202386bd593d81f7f`
  when this design was written.
- Runner group 8 is selected, allows the public Disk repository, is restricted
  to `.github/workflows/release-deploy.yml@refs/heads/main`, and contains zero
  runners.
- The staging and production environments admit `main` only.
- `arcana-devs` is unsuitable in place: it has three installed runner services
  and its root filesystem is 99 percent full.
- `arcana-agents` is unsuitable in place because it carries production agent
  workloads and two runner services, but it has a KVM device, 57 GiB available
  memory, and 234 GiB free disk for a separate guest boundary.

These measurements are discovery evidence, not durable future-state claims.
Provisioning must recheck them immediately before mutation.

## Alternatives considered

1. **Install another runner directly on a fleet host — rejected.** The reviewed
   readiness job requires exactly one installed and active runner system unit
   in its systemd namespace. Direct installation also risks shared groups,
   Docker access, and workspace access.
2. **Use a systemd-nspawn guest — rejected.** It is lighter, but shares the
   production host kernel. That is unnecessary when hardware virtualization is
   already available.
3. **Use a KVM guest — selected.** It gives a separate kernel, systemd and
   cgroup namespace, user database, filesystem, and network boundary while
   consuming only existing capacity.

## Guest contract

The guest must satisfy the load-bearing checks already present on `main`:

- the runner executes as a non-root user in group `disk-arcana-deploy`;
- subordinate UID and GID ranges are each at least 65536;
- rootless user namespaces, user systemd, linger, and Podman are available;
- no Docker socket is present or writable;
- exactly one `actions.runner.*` system service is installed and active, and
  the job process is bound beneath that service's cgroup;
- `sudo -n -l` exposes exactly
  `(root) NOPASSWD: /usr/local/sbin/disk-arcana-deploy-broker --deploy *`;
- `disk-arcana-server.service` is active and exactly enabled with
  `Restart=on-failure`, `StartLimitIntervalUSec=2min`, and
  `StartLimitBurst=5`;
- `http://127.0.0.1:9446/health` succeeds without persisting its body; and
- the actionless probe reads fresh `origin/main` and requires exact equality
  with both workflow SHAs.

The runner registers at organization scope directly into group 8 with label
`disk-arcana-stage`. The group remains restricted to the exact workflow on
`refs/heads/main`; environment branch policies remain unchanged.

## Tracked components

Provisioning is repository-owned and reviewed before use:

- a host-side script creates the guest disk and seed, verifies immutable input
  digests, installs the host systemd unit, and starts only the guest;
- a guest bootstrap script creates the runner user, installs rootless Podman
  prerequisites, installs the server unit and broker from an exact-main bundle,
  and configures the single runner service;
- a teardown script stops and disables only this guest, deregisters only its
  runner identity, and preserves a diagnostic copy unless explicit purge is
  requested; and
- shell tests execute the isolated privileged bootstrap, registration cleanup,
  fresh-authority API revocation, exact binding, teardown API deletion, path
  validation, digest rejection, secret redaction, and crash-resume phases.

Direct downloads are forbidden unless the artefact digest is checked against a
separately authenticated manifest. The complete cloud-init pair is likewise
bound to one separately frozen, reviewed digest before seed creation. GitHub
registration material is never logged, committed, or placed in cloud-init.
The mode-0600 recovery record persists identity metadata, not expiring runner
tokens. Recovery requires a separately supplied, root-owned mode-0600 GitHub
API token, proves the organization and group-8 views agree on zero runners or
one exact runner, and deletes authority only after durable `COMMITTED` or
`RECOVERED`. Provisioning fails closed if it cannot preserve that bounded
recovery and deletion contract.

## Control flow and failure handling

1. Re-fetch and freeze exact `origin/main`; verify the relevant CI and Windows
   runs are terminal-success for that SHA.
2. Recheck host capacity, KVM access, loopback management-port availability,
   and absence of an existing guest or runner identity.
3. Build and verify guest inputs in a private staging directory. No host service
   is installed until every digest and configuration check passes.
4. Atomically install the guest disk, seed, and host unit; start the guest and
   wait on explicit health conditions rather than fixed sleeps.
5. Bootstrap the guest, then register the runner only after every local
   readiness predicate except runner binding passes.
6. Dispatch `release-deploy.yml` from exact `main` with
   `target=stage-probe`. Terminal success and the `readiness=ok` marker are the
   live proof.

Any failure before registration removes staged guest state. A hard interruption
is resumed from the protected phase journal: pre-registration authority is
discarded only after terminal `RECOVERED`, while a registration-intent or later
phase uses fresh GitHub API authority to revoke the exact group-8 singleton
without depending on one-hour registration/removal tokens. A failure after
registration first stops the runner, then deregisters that exact identity,
then stops the guest. Existing host runners, Docker workloads,
production service, runner groups, environment policies, and INFRA-0389 are
never modified.

## Threat model

The protected assets are production workloads on the host, organization-wide
runner capacity, GitHub registration material, and the deployment broker.
Primary threats are host escape, accidental selection by another workflow,
credential persistence, broad sudo, host Docker access, stale-main execution,
and teardown targeting the wrong runner. The separate KVM kernel, outbound-only
networking, loopback-only administration, exact workflow restriction, exact
sudo rule, immutable identity checks, and target-specific rollback address
those threats. The guest is not a general CI runner.

## Verification

- Fresh-process RED/GREEN tests prove each negative is load-bearing: wrong
  digest, wrong guest path, writable Docker socket, extra sudo command, extra
  runner unit, disabled service, stale main, wrong runner identity, incomplete
  labels, foreign group members, expired runner-token recovery, authority
  deletion ordering, unregistered-host cleanup, and diagnostics symlinks.
- Run ShellCheck, actionlint, all Linux deployment contract suites, and the
  repository's relevant full verification on the immutable PR head.
- After protected delivery, compare resulting-main blobs and rerun exact-main
  CI before provisioning.
- Run the actionless stage probe once. Do not dispatch production deployment.
- Verify the original dirty INFRA-0370 worktree and INFRA-0389 row are
  byte-unchanged.

## Rollback

Rollback targets only the named guest and runner identity. It stops the guest,
disables its host unit, and either deregisters the manifest-bound ID or resolves
an `UNREGISTERED` manifest against matching complete organization and group-8
inventories before deleting the sole exact runner. A hard crash after canonical
state installation but before unit installation is recoverable only when the
protected host phase is exactly `READY_TO_INSTALL` and both inventories are
empty. Rollback rejects foreign/multiple runners and diagnostics paths with
symlink components, then moves guest state to a timestamped diagnostic
directory. Purging that directory is a separate destructive action.

## Non-goals

- No production deployment or restart.
- No change to group 8 restrictions or environment branch policies.
- No reuse of `ci-general`, production, database, or existing agent runner
  identities.
- No INFRA-0389 remediation, runner-capacity rebalance, or deletion of foreign
  worktree changes.
- No claim that a successful code test substitutes for the live stage probe.

## Acceptance criteria

1. Provisioning and teardown artefacts are tracked, reviewed, mutation-tested,
   and delivered through protected `main`.
2. The guest passes every reviewed local readiness predicate without host
   Docker access or broad privilege.
3. Group 8 contains exactly the new online idle runner with the required label
   and retains its exact workflow restriction.
4. The actionless `stage-probe` run completes successfully at fresh exact main
   and emits `readiness=ok`.
5. Production state, existing fleet runner identities, environment policies,
   INFRA-0389, and the original foreign worktree changes remain unchanged.
