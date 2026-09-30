# Retired workflows

Workflows moved here do not run: GitHub Actions only schedules files in `.github/workflows/`. They are kept in-tree so
that restoring one is a `git mv` back.

| workflow | retired | why | reverse_if (move it back when ALL hold) |
|---|---|---|---|
| `deploy-arcana-agents-share.yml` | 2026-09-30 (Control 19:12Z, deploy-preflight wave 1) | It runs on `[self-hosted, Linux, X64, arcana-agents]`. That host was decommissioned by INFRA-0417 on 2026-09-17 and no runner carries the label. The Disk Arcana server it delivers the share drop-in to has **no host** since then: measured 2026-09-30, the unit is absent on arcana-prd and arcana-devs; Muneral card `00f3c8e2`. | (1) The Disk Arcana server is deployed on a live host (card `00f3c8e2` closed). (2) A runner on that host carries the label the job targets, and the repository is on its group's allowlist. (3) The restored job runs `scripts/ci/runner-broker-preflight.sh` (canonical blob `273ee95b`) before its `sudo` step. |
