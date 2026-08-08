# DISK-RB-014 — updating the server on `arcana-agents` (canon Datarim KB host)

`arcana-agents` holds the canon `datarim-kb` share. It is **outside every
automated delivery path in this repository**, so a fix merged to `main` does not
reach it. This runbook records the measured constraints so the next person does
not rediscover them, and states what has to happen for an update to land.

Written while closing DISK-0071, where four merged fixes could not be applied to
the one host that needed them.

## Why the existing workflows do not cover this host

Measured on 2026-08-04, not inferred:

| Path | Why it does not apply |
|---|---|
| `release-deploy.yml` → `deploy-stage` | Targets `arcana-devs` only through the system-service deployment broker. |
| `release-deploy.yml` → `deploy-prod` | Targets `arcana-prod` through the same system-service deployment broker. |
| `deploy-unit.yml` | Delivers unit files, not binaries. Its `arcana-agents` target (added in DISK-0070) covers the **share drop-in** only. |

And the host itself differs from both deploy targets:

- **A decoy system unit exists.** `/etc/systemd/system/disk-arcana-server.service`
  is present but `inactive` and `disabled`; the server actually runs from
  `/home/dev/.config/systemd/user/disk-arcana-server.service`. So
  `systemctl restart disk-arcana-server` — the system-service operation used by the broker —
  succeeds against the wrong, dormant unit and changes nothing, while the step
  reports success. Restarting the live server requires `systemctl --user` in
  `dev`'s session.
- **The health check would pass against nothing.** `deploy-dev` probes
  `http://127.0.0.1:9446/health`, but this host serves health on
  `DISK_HEALTH_BIND_ADDR=100.108.24.109:9546`; nothing listens on `:9446`. A
  naive copy of that path would therefore fail its probe, roll back, and report a
  failure whose cause is the wrong port rather than the binary.
- `/usr/local/bin/disk-arcana-server` is `root:root 0755`, and `/usr/local/bin`
  is **not writable** by `dev`;
- the CI runner on this host executes as `support-proof`, and
  `sudo -n -l -U support-proof` reports *"User support-proof is not allowed to run
  sudo on arcana-agents"* — so the runner cannot install a root-owned binary nor
  reach `dev`'s systemd session;
- there is **no clone of this repository** on the host.

Net effect: installing a new binary needs a root channel that no automated path
currently has. That is a provisioning decision, not something a workflow tweak
can paper over.

## What an update requires

Pick one; both are deliberate choices, not equivalents:

1. **Give the host a real delivery path.** Add an `arcana-agents` job to
   `release-deploy.yml` that (a) installs the binary through a root broker in the
   style of `deploy/linux/install-disk-arcana-install-unit-broker.sh`, and
   (b) restarts the **user** unit in `dev`'s session rather than the system one.
   This is the durable answer; it also makes the host's state reproducible.
2. **Update by hand, once, with the steps recorded.** Acceptable only as a
   stopgap, and it must be logged in the task that authorised it — hand-updated
   hosts are exactly how this host drifted out of version control in the first
   place (its share drop-in had no source in the repo until DISK-0070).

## After the binary changes: clearing stale tombstones

The DISK-0071 fixes stop *new* bad tombstones and add a way to repair old ones,
but they only take effect once the new binary runs. Afterwards:

1. Confirm the running build actually contains the fix — do not infer it from a
   merge SHA.
2. Trigger a reconciliation. `full_reconcile` upserts every file it finds, and an
   upsert clears `deleted`, so rows whose bytes are present come back live.
3. Read the count it reports: a non-zero `revived` in the server log names how
   many paths were silently undeliverable. Zero on a second pass is the success
   signal.
4. Do **not** edit `files.deleted` in the live MetaDb by hand. Take a backup
   first regardless (`/tmp/disk.db.bak-DISK-0070` was taken before the DISK-0071
   investigation, 9015296 B).

## Health signals that lie

Two metrics on this path look authoritative and are not — both measured during
DISK-0071:

- `bytes_received_session` stays `0` even for files that demonstrably arrived;
- `last_success_at` refreshes every second, so a share that is replicating
  nothing still looks freshly successful. `state=syncing` with
  `last_error=null` was reported throughout a total replication outage.

Verify replication by writing a probe file into canon and checking it appears on
the follower — not by reading either counter.
