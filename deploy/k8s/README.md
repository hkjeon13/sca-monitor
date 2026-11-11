# SCA Monitor on the server-4096 k3s node

The API Deployment and three CronJobs use the existing SQLite database and runtime
directory on the same node. The repository analysis worker stays in the host
`sca-monitor-repository-worker.timer`: its KVM launcher and privileged host
systemd helper are outside the container security boundary. The temporary ZIP
prune timer also stays on the host because it operates on the host checkout.

This is a single-node deployment. `hostPath`, `imagePullPolicy: Never`, and the
fixed node selector make a replacement node or a containerd image cleanup a
recovery event. A registry-backed image and persistent database storage are
needed before multi-node operation.

## Preparation

1. Preserve the current host checkout and `.env`. Build an image from the
   complete source tree, including any host-only uncommitted changes, with the
   versioned tag in both YAML files. Import it into the k3s containerd store.
2. Create the `sca-monitor` namespace and a Secret from the protected host
   `.env`. Keep the Secret out of Git and terminal output.
3. Apply `sca-monitor-jobs.yaml`. Its CronJobs start suspended.
4. Deploy `sca-monitor.yaml` with `hostPort: 18782` for staging. Check
   `http://127.0.0.1:18782/ready`, the UI, authentication, and the repository
   capability response. The old host API continues on `18780`.
5. Use `scripts/backup_database.py --required` and
   `scripts/verify_backup_restore.py` against the actual SQLite path. Record
   the unique backup path and verify the restored schema before cutover.

## Cutover

1. Confirm no source sync or project worker invocation is active. Stop the
   `sca-monitor-project-worker.timer`, `sca-monitor-source-sync.timer`, and
   `sca-monitor-exploit-sync.timer` on the host; wait for their services to
   finish. Keep the repository KVM worker and ZIP prune timer running.
2. Stop `sca-monitor-api.service` on the host. Apply `sca-monitor.yaml` with
   `hostPort: 18780`. Wait for rollout and confirm both
   `http://127.0.0.1:18780/ready` and the public HTTPS `/ready` return 200.
3. Unsuspend the three Kubernetes CronJobs and inspect their first results.
   Keep the old systemd unit files and the database backup intact.

## Rollback

Suspend the three Kubernetes CronJobs, set the API Deployment back to staging
port `18782` (or scale it to zero), then start the old host API and the three
host timers. Check the public HTTPS `/ready` and the worker results. The
database remains at the original host path throughout, so switching traffic
back does not copy or replace it. If a later schema or data change makes the
old code incompatible, restore from the verified backup in a separate,
reviewed recovery operation.

Devtron's Resource Browser can observe these native Kubernetes workloads.
They are applied with `kubectl` rather than a Devtron application pipeline;
registering them in a Devtron deployment workflow is a separate source and
registry integration step.
