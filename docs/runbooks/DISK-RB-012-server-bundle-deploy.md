# DISK-RB-012 — deploy the manifest-bound server bundle

Use this procedure to deploy the Disk Arcana system service to `arcana-devs`
or `arcana-prod`. It is a how-to for the tracked release path; it is not an
alternative manual deployment path.

## Safety boundary

- Deploy only a commit already merged to `main` with required CI and review.
- Use `.github/workflows/release-deploy.yml`. Do not copy the binary or unit to
  a host, run the bundle's helper as the runner, or restart the service by hand.
- Run `target=stage` first. `target=prod` builds once, deploys that same-run
  artifact to staging, and permits production only after staging succeeds.
- Never retry a failed production job. Preserve its transaction record and
  investigate the terminal state.
- Never print `/etc/disk-arcana/env`, authorization material, workflow tokens,
  or raw health/configuration bodies into evidence.

The bundle contains exactly the binary, systemd unit, cold-host installer,
deployment helper, broker, provisioner, sudoers policy, commit file, and
`manifest.sha256`. The
upload action emits an immutable artifact ID and digest. Each deploy job selects
that ID, relies on the download action's digest validation, and independently
checks the manifest digest and commit before invoking the installed broker.

## One-shot broker bootstrap

Bootstrap is a separately authenticated root operation. It must not run in a
GitHub workflow or through the CI runner's sudo access.

1. From the approved tailnet root channel, create the service-independent
   `/var/lib/disk-arcana-deploy` root and its `transactions` and
   `bootstrap/<deployment-id>` children as `root:root 0700`. Never place deploy
   journals, authorizations, inboxes, or backups under the service-writable
   `/var/lib/disk-arcana` tree.
2. Put the exact merged bundle and a `root:root 0600` authorization file in that
   directory. The file contains only these newline-delimited keys:
   `deployment_id`, `run_id`, `commit`, `manifest_sha`, `hostname`, `nonce`,
   `expires`, `runner_user`, `runner_group`, `import_root`, and
   `bootstrap_root`. Use `runner_group=disk-arcana-deploy`; bind
   `bootstrap_root` to the canonical directory above and `import_root` to that
   runner's exact `RUNNER_TEMP` parent.
3. Confirm the authorization expiry is in the future and the nonce has never
   been used. The packet carries no credential.
4. If the target is cold (both live binary and unit absent), first place its
   protected staging configuration under `/etc/disk-arcana`. Keep the env and
   key material out of the bundle and evidence. Run the bundle's cold installer
   with its journal in the already root-issued bootstrap directory:

   ```text
   bash /var/lib/disk-arcana-deploy/bootstrap/<deployment-id>/bundle/install.sh \
     --binary /var/lib/disk-arcana-deploy/bootstrap/<deployment-id>/bundle/disk-arcana-server \
     --unit /var/lib/disk-arcana-deploy/bootstrap/<deployment-id>/bundle/disk-arcana-server.service \
     --journal-dir /var/lib/disk-arcana-deploy/bootstrap/<deployment-id> \
     --expected-hostname <static-hostname>
   ```

   Require `state=COMMITTED health=ok`, active/enabled readback, and copy the
   secret-free journal hash to the protected DEVS audit record before the
   broker provisioner removes the bootstrap directory. A crash before commit
   is recovered by invoking the same exact installer once; it restores the
   absent binary/unit/account/directory baseline and returns failure.
5. Run the bundle's reviewed broker provisioner as root:

   ```text
   bash /var/lib/disk-arcana-deploy/bootstrap/<deployment-id>/bundle/provision-deploy-broker.sh \
     --bundle /var/lib/disk-arcana-deploy/bootstrap/<deployment-id>/bundle \
     --authorization /var/lib/disk-arcana-deploy/bootstrap/<deployment-id>/authorization
   ```

6. Require `state=COMMITTED`. Confirm the bootstrap directory is absent, the
   nonce is recorded below `/var/lib/disk-arcana-deploy/transactions`, and a
   second use is rejected. This removal is the bootstrap end-of-life proof.
7. Read back `sudo -ln -U <runner-user>`. The only task-owned NOPASSWD grant may
   be `/usr/local/sbin/disk-arcana-deploy-broker --deploy *`. Any wildcard
   systemctl, journalctl, shell, `SETENV`, or other broader grant is a failure.

The bootstrap journal uses these states:

```text
AUTHORITY_ISSUED -> BACKUP_WRITTEN -> INSTALLED -> NARROW_RULE_VERIFIED
-> BOOTSTRAP_REVOKED -> COMMITTED
```

An interruption before bootstrap revocation restores the prior helper, broker,
sudoers, config, group membership, and group existence, then revokes the old
authorization. It finishes as `FAILED_RECOVERED`; issue a new authorization to
try again. An interruption after `BOOTSTRAP_REVOKED` verifies the installed
generation and rolls forward to `COMMITTED`. `FAILED_RECOVERY_REQUIRED` is a
hard stop for root investigation.

## Root-issued routine authorization

The runner is not a payload-signing authority. Before approving each protected
`staging` or `production` environment job, a root operator independently reads
the pending run's repository, exact-main workflow ref, run ID/attempt, commit,
artifact ID/digest, manifest SHA-256, target, and static hostname. Write those
fields with a fresh nonce and short expiry to:

```text
/var/lib/disk-arcana-deploy/authorizations/<run-id>-<attempt>-<target>.auth
```

Use `root:root 0600`; both the authorization directory and its `consumed`
child are `root:root 0700`. The file contains exactly `repository`,
`workflow_ref`, `run_id`, `run_attempt`, `target`, `commit`, `artifact_id`,
`artifact_digest`, `manifest_sha`, `hostname`, `nonce`, and `expires`.
`workflow_ref` is fixed to
`Arcanada-one/disk-arcana/.github/workflows/release-deploy.yml@refs/heads/main`.
This packet is authorization metadata, not a credential. The installed broker
derives commit/hostname/manifest from it, atomically moves it into `consumed`
before activation, and rejects replay. Do not approve the environment until the
packet is fsynced and its non-secret field set has been independently checked.

## Dispatch and evidence

For a staging rehearsal, dispatch `Release + Deploy` on exact `main` with
`target=stage`. Create the matching root authorization, then approve the
protected `staging` job. For production, dispatch it once with `target=prod`;
create both same-run target authorizations and approve each environment only
at its gate. Do not
reuse the prior staging artifact or select an artifact from another run.

Retain these non-secret fields from the run:

- workflow run ID and exact merged commit;
- artifact ID, artifact SHA-256 digest, and manifest SHA-256;
- target runner name, static hostname, and non-root runner identity;
- installed binary and unit SHA-256 values;
- `ActiveState=active`, `UnitFileState=enabled`, `Restart=on-failure`,
  `StartLimitIntervalUSec=2min`, and `StartLimitBurst=5`;
- bounded health success and the terminal transaction state;
- the corresponding root transaction-record basename, not its protected
  contents.

Apply the identical bundle a second time on staging. A successful reapply must
report `state=COMMITTED idempotent=true` and create no new backup.

## Failure and recovery

The release-update helper persists these states under
`/var/lib/disk-arcana-deploy/transactions`:

```text
BACKUP_WRITTEN -> FILES_STAGED -> FILES_ACTIVATED -> DAEMON_RELOADED
-> SERVICE_RESTARTED -> HEALTH_VERIFIED -> COMMITTED
```

On synchronous failure after backup, or on the next invocation after a crash,
the helper restores both the prior binary and unit, reloads systemd, restarts
the prior generation, and proves active health. `FAILED_RECOVERED` means that
recovery completed; stop the run and diagnose before issuing a new deployment.
`FAILED_RECOVERY_REQUIRED` means automatic recovery could not prove the prior
generation. Do not edit either target or journal. Preserve:

```text
systemctl status disk-arcana-server --no-pager
systemctl show disk-arcana-server -p ActiveState -p Restart \
  -p StartLimitIntervalUSec -p StartLimitBurst
sha256sum /usr/local/bin/disk-arcana-server \
  /etc/systemd/system/disk-arcana-server.service
```

Escalate with the workflow run, commit, artifact/manifest identities, terminal
state, and transaction-record basename. A root operator may inspect the
protected journal and backup, but must use the installed helper's recovery on a
fresh invocation; manual file replacement is not a supported recovery action.

Backups below `/var/lib/disk-arcana-deploy/backups` are root-only recovery
evidence. Retain the current successful generation and the immediately prior
generation until the next independently verified deployment. Remove older
records only through an explicitly authorized retention task, never inside the
deployment workflow.
