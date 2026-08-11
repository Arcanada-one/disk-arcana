# INFRA-0370 Dedicated Stage Runner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `subagent-driven-development` (recommended, when your runtime supports spawning isolated agents) or `executing-plans` (single-session execution) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provision one reviewed, isolated staging guest that can execute the existing actionless `stage-probe` and prove test/production durability symmetry.

**Architecture:** A host script creates an outbound-only KVM guest from verified immutable inputs; a guest script establishes the exact runner, broker, Podman, systemd, and health contract; a teardown script targets only the recorded guest and GitHub runner identity. Code reaches protected `main` before live provisioning.

**Tech Stack:** Bash strict mode, QEMU/KVM, cloud-init, systemd, GitHub Actions self-hosted runner, Podman, ShellCheck, actionlint, and existing Linux deployment contract suites.

---

### Task 1: Freeze the provisioning contract

**Files:**
- Create [to-be-created]: `deploy/linux/tests/test-stage-runner-provisioning.sh`
- Modify: `.github/workflows/ci.yml`

- [ ] Add the suite beside `test-release-deploy-contract.sh` in CI.
- [ ] Start the suite with the intended RED:

```bash
for required in \
  deploy/linux/provision-stage-runner-host.sh \
  deploy/linux/bootstrap-stage-runner-guest.sh \
  deploy/linux/teardown-stage-runner-host.sh \
  deploy/linux/systemd/disk-arcana-stage-vm.service.in; do
  [[ -f "$REPO_ROOT/$required" ]] || fail "missing $required"
done
```

- [ ] Run `bash deploy/linux/tests/test-stage-runner-provisioning.sh` and require
  non-zero with `missing deploy/linux/provision-stage-runner-host.sh`.
- [ ] Add fake-root negatives for wrong digests, relative/symlink paths,
  foreign state, token mode, secret persistence, broad sudo, writable Docker,
  extra runner units, phase rollback, runner identity mismatch, and idempotence.
- [ ] Commit with `test(infra): specify isolated stage runner provisioning`.

### Task 2: Implement verified host-side guest creation

**Files:**
- Create [to-be-created]: `deploy/linux/provision-stage-runner-host.sh`
- Create [to-be-created]: `deploy/linux/systemd/disk-arcana-stage-vm.service.in`
- Test: `deploy/linux/tests/test-stage-runner-provisioning.sh`

- [ ] Implement strict mode and only these arguments:

```text
--state-root --cloud-image --cloud-image-sha256 --guest-bundle
--guest-bundle-sha256
--runner-archive --runner-archive-sha256 --management-port
```

- [ ] Require UID 0, absolute non-symlink state under
  `/var/lib/disk-arcana-stage`, two lowercase 64-hex digests, `/dev/kvm`, a
  free numeric loopback port, and absence of foreign guest/unit state.
- [ ] Require the cloud-init pair to match a separately frozen, reviewed
  `--guest-bundle-sha256` and persist that digest in the state manifest.
- [ ] Verify inputs before creating state; build in a mode-0700 sibling staging
  directory; journal each phase in mode 0600; atomically install only after
  qcow2, NoCloud seed, and rendered unit validate.
- [ ] Require the unit to use KVM, private QEMU user networking, loopback-only
  SSH forwarding, no reboot, and no host filesystem or Docker-socket mounts.
- [ ] Run normal host cases GREEN, then neuter the image-digest check and
  require the wrong-digest fixture to turn RED for guest-state creation.
- [ ] Commit with `feat(infra): create verified stage runner guest`.

### Task 3: Implement guest bootstrap and privilege boundary

**Files:**
- Create [to-be-created]: `deploy/linux/bootstrap-stage-runner-guest.sh`
- Test: `deploy/linux/tests/test-stage-runner-provisioning.sh`

- [ ] Before authority mutation, require a root-owned mode-0700 bootstrap root
  holding `bundle/`, `runner.tar.gz`, its digest, and a root-owned mode-0600
  registration file. Install a failure trap before reading it.
- [ ] Install only signed Ubuntu packages; create non-root user `disk-stage`,
  group `disk-arcana-deploy`, 65536 subordinate UID/GID ranges, user systemd,
  linger, and Podman. Docker and writable Docker sockets are forbidden.
- [ ] Reuse `deploy/linux/install.sh` and
  `deploy/linux/provision-deploy-broker.sh` for the server and exact broker
  policy; do not duplicate their authority logic.
- [ ] Register the organization runner into group `disk-arcana-stage` with
  name and label `disk-arcana-stage`, install exactly one
  `actions.runner.*` system unit, and remove registration material immediately.
- [ ] Before consuming registration authority, persist a root-only recovery
  identity record plus phase journal without caching expiring runner tokens.
  On an incomplete rerun, `--recover-only` requires a fresh root-owned GitHub
  token, proves complete organization/group-8 agreement, revokes the sole exact
  runner if present, and durably enters terminal `RECOVERED` before deleting
  any authority, without rerunning bootstrap mutations.
- [ ] Start the runner only after service active/enabled, health, restart
  limits, exact sudo, Podman, userns, subordinate IDs, and Docker negative pass.
- [ ] Execute the isolated privileged bootstrap and a post-registration
  failure; require exact package/user/registration/install/readiness markers,
  runner revocation, terminal journaling, and killed rollback mutants.
- [ ] Commit with `feat(infra): bootstrap broker-only stage runner`.

### Task 4: Implement identity-bound teardown

**Files:**
- Create [to-be-created]: `deploy/linux/teardown-stage-runner-host.sh`
- Test: `deploy/linux/tests/test-stage-runner-provisioning.sh`

- [ ] Require a mode-0600 state manifest with the fixed guest name, absolute
  state root, host unit, runner name, and a numeric ID or exact
  `UNREGISTERED` sentinel.
- [ ] For a numeric identity, require exact API ID/name readback. For
  `UNREGISTERED`, stop the VM, require complete organization and group-8 views
  to agree on zero runners or one idle exact-label singleton, and persist every
  destructive intent before deletion.
- [ ] Recover the post-state-move/pre-unit-install crash interval only when the
  protected host phase is exactly `READY_TO_INSTALL`, the unit is absent, and
  complete organization/group-8 inventories are both empty; reject every
  other missing-unit state before a teardown journal is created.
- [ ] Stop/disable only the recorded unit, deregister only that runner, and
  move guest state to timestamped diagnostics. Never purge diagnostics.
- [ ] Test changed name/ID/path/unit, foreign runner/group membership,
  unregistered recovery, API deletion, unit-removal interruption, and a
  diagnostics-root symlink. Identity/path mismatches must fail closed; a
  safely stopped ambiguous guest remains resumable without runner deletion.
- [ ] Neuter the ID check and require the wrong-ID fixture to turn RED for a
  deregistration attempt.
- [ ] Commit with `feat(infra): add identity-bound stage teardown`.

### Task 5: Verify and deliver immutable code

**Files:**
- Verify all paths changed by Tasks 1-4

- [ ] Run focused suites:

```bash
bash deploy/linux/tests/test-stage-runner-provisioning.sh
bash deploy/linux/tests/test-release-deploy-contract.sh
bash deploy/linux/tests/test-deploy-broker.sh
bash deploy/linux/tests/test-deploy-server.sh
```

- [ ] Run static checks:

```bash
shellcheck deploy/linux/provision-stage-runner-host.sh \
  deploy/linux/bootstrap-stage-runner-guest.sh \
  deploy/linux/teardown-stage-runner-host.sh \
  deploy/linux/tests/test-stage-runner-provisioning.sh
actionlint .github/workflows/*.yml
git diff --check origin/main...HEAD
```

- [ ] Push the exact branch and open a protected PR listing fresh-process
  RED/GREEN evidence. Do not enable auto-merge.
- [ ] Require exact-head terminal-success CI and immutable independent review.
- [ ] Land only through the protected path, then prove resulting-main blob
  equality plus exact-main CI and Windows success before live work.

### Task 6: Provision and prove the live boundary

**Files:**
- Execute only reviewed artefacts from resulting `origin/main`

- [ ] Recheck host identity/capacity/KVM/port, absence of guest/unit/runner,
  exact group-8 workflow restriction, and both environment branch policies.
- [ ] Acquire Ubuntu and runner inputs from official channels; verify signature
  and SHA-256 manifests; create the exact-main deployment bundle in mode 0700.
- [ ] Run reviewed provisioning. Read back guest path/unit, runner
  ID/name/group/labels/status, exact sudo, Docker negative, Podman/userns,
  service enabled/active, health, and restart limits.
- [ ] Dispatch `.github/workflows/release-deploy.yml` from exact `main` with
  `target=stage-probe`. Require terminal success at that SHA and
  `readiness=ok`. Never dispatch `stage` or `prod` in this task.
- [ ] Record exact main, PR/resulting-main proof, runner-group readback, probe
  run ID, service state, and unchanged production/INFRA-0389/foreign-dirt
  checks. Only then mark the lane complete.

## Path validation

```text
PATH VALIDATION
  checked:    12 path references
  present:    7
  MISSING:    none
  to-create:  deploy/linux/tests/test-stage-runner-provisioning.sh,
              deploy/linux/provision-stage-runner-host.sh,
              deploy/linux/systemd/disk-arcana-stage-vm.service.in,
              deploy/linux/bootstrap-stage-runner-guest.sh,
              deploy/linux/teardown-stage-runner-host.sh
  DEPRECATED: none
```

The seven existing paths were resolved from the git index or filesystem. The
five absent paths are explicit creation targets rather than assumed inputs.
