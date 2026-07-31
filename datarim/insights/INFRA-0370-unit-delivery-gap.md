# INFRA-0370 — a config file in git is not a config file on the host

**Date:** 2026-07-31
**Context:** Moving `StartLimitIntervalSec` / `StartLimitBurst` from `[Service]`
to `[Unit]` in `deploy/linux/disk-arcana-server.service`.

## Finding

`release-deploy.yml` deploys by:

1. downloading the built binary artefact,
2. `cp` into `/usr/local/bin/`,
3. `systemctl restart disk-arcana-server`,
4. health-check with rollback of the **binary**.

At no point does it copy `deploy/linux/disk-arcana-server.service` to
`/etc/systemd/system/`. The repo file is a *template that a human once installed
by hand*, not a deployed artefact.

So the whole restart-limit correction was inert. The unit in git would be right,
CI would be green, the PR would read as complete — and `systemctl show` on prod
would keep reporting systemd's default start-rate limit, because the host still
runs whatever unit was installed manually months ago. Worse, the failure is
invisible: nothing in the pipeline compares the two.

## Why this class is easy to miss

The task reads as "edit a file". The file is in the repo, under a `deploy/`
directory, next to things that *are* deployed. Nothing about the diff hints that
the delivery path stops short of it. The tell is asking a different question:
**"after this merges, what command puts this byte sequence on the host?"** If
there is no answer, the change is documentation.

## Generalisation

For any change to a file under `deploy/`, `etc/`, `config/`, or similar, check
whether the pipeline ships it or only ships the binary next to it. Config drift
between repo and host is silent by construction — a digest comparison has to be
added deliberately.

## What was done

- `scripts/install-systemd-unit.sh` — `--dry-run` (diff repo vs installed),
  `--install` (backup → install → `daemon-reload` → restart → health-check →
  restore backup on failure), `--verify` (assert the **loaded**
  `StartLimitIntervalUSec` / `StartLimitBurst`).
- `.github/workflows/deploy-unit.yml` — `workflow_dispatch`, defaults to
  `dry-run` so the destructive path is opt-in.

Verification asserts the *loaded* values via `systemctl show`, not the file
contents. That distinction is the entire point of the original bug: systemd
accepts `StartLimitBurst` under `[Service]` syntactically and ignores it, so
grepping the installed file proves nothing. Only the parsed value does.

## Related

[[INFRA-0370-action-pinning]] — the other silent-failure class in the same task:
a pin that looks valid and is not.
