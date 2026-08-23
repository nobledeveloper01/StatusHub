# Deploying StatusHub

Two artefacts, deliberately separate:

- **`terraform/`** provisions what has to exist before a pod starts and has
  to outlive one: the database, the secrets, the audit bucket, the network
  boundary.
- **`helm/`** runs the workloads.

Terraform does not template Deployments and the chart does not create
databases. Two places disagreeing about replica counts is a bad afternoon the
first time somebody scales in a hurry.

## The shape, and why

```
providers ──▶ receiver (3+)         api (2)         [dispatcher (2)]
              latency-critical      operator-facing  throughput-bound
              scales on rps/p99                      scales on queue depth
```

**The receiver and the dispatcher are separate Deployments.** Not for tidiness
— because the receiver must stay available when the dispatcher is entirely
down. A single Deployment has one readiness probe, and a shared probe takes
the receiver out of rotation for a dispatcher fault, losing precisely the
events persist-then-acknowledge exists to protect.

Their probes differ for the same reason:

| | Readiness | Liveness |
|---|---|---|
| **Receiver** | Can it write a raw event — nothing else | Is the process alive |
| **Dispatcher** | none: it serves nothing | none |
| **API** | Can it reach the store | Is the process alive |

Liveness never points at `/readyz`. A liveness probe that fails on a slow
database restarts a healthy process, turning a brief outage into a restart
loop.

Try it: `kubectl delete pod -l app.kubernetes.io/component=dispatcher` while
events are arriving. The receiver keeps answering 200 and delivery catches up.

## Quick start

```bash
terraform -chdir=deploy/terraform apply \
  -var name_prefix=acme -var environment=live \
  -var vpc_id=vpc-… -var 'private_subnet_ids=["subnet-a","subnet-b"]' \
  -var application_security_group_id=sg-…
```

Sync the resulting secret into a Kubernetes Secret named `statushub` with
keys `database-url`, `tenant-salt-master` and `audit-checkpoint-seed` — via
External Secrets or the Secrets Store CSI driver, rather than copying values,
so rotation happens in one place.

```bash
helm install statushub deploy/helm/statushub \
  --set config.baseURL=https://hooks.example.com \
  --set config.environment=live
```

Then, before pointing a provider at it:

```bash
kubectl exec deploy/statushub-api -- statushubctl doctor
```

## Decisions worth knowing before you change them

**No CPU limit on the receiver.** Requests reserve capacity; limits only
throttle. A throttled receiver misses its 50 ms budget, the provider retries,
and a capacity problem becomes a duplicate-events problem.

**`maxUnavailable: 0` on the receiver, `1` on the dispatcher.** A receiver
rollout that dips capacity drops provider connections. A dispatcher rollout
cannot lose anything: deliveries are leased, and a replica that disappears has
its lease reclaimed.

**`terminationGracePeriodSeconds` exceeds the app's own drain.** Otherwise
Kubernetes kills the process mid-drain and the graceful shutdown is
decorative. It must also exceed the longest single delivery attempt, or a
rolling deploy severs a request the customer's endpoint is still answering —
and they get the event twice.

**Migrations are a `pre-upgrade` hook, not an init container.** An init
container runs once per pod, so a three-replica rollout races three migrations
against each other. The runner takes an advisory lock and would survive that,
but a deploy whose correctness depends on a lock is one nobody can reason
about at three in the morning.

**Two ingresses, not one.** The receiver is public by necessity; the
management API is not. Behind one hostname, any IP restriction or WAF rule
protecting the API also applies to the receiver — and a provider adding an
egress range you did not know about then fails valid events at the edge, where
you cannot see them.

**A PodDisruptionBudget on the receiver only.** The dispatcher can be entirely
absent for minutes without an event being lost, and blocking a cluster upgrade
for it would be protecting the wrong thing.

**Object lock in COMPLIANCE mode on the audit bucket.** Governance mode can be
overridden by a sufficiently privileged principal, which is exactly the
principal an attacker is trying to become. It also cannot be shortened
afterwards, by anybody — including you.

**`ignore_changes` on the tenant salt master.** Replacing it re-derives every
tenant's salt and orphans every customer hash already stored: correlation
breaks across the boundary and an erasure request matches only half a
subject's events. Terraform must not do that as a side effect of a provider
upgrade regenerating a random value. See
[ADR-004](../docs/adr/0004-derive-tenant-salts-from-one-master.md).

## Multi-region

Receivers in every region; the dispatcher, normaliser and API in exactly one
([ADR-006](../docs/adr/0006-multi-region.md)).

```bash
# The primary: everything.
helm install statushub deploy/helm/statushub \
  --set region.name=us-east-1 --set region.role=primary \
  --set config.baseURL=https://hooks.example.com

# An edge region: receivers only, writing to the primary's database.
helm install statushub deploy/helm/statushub \
  --set region.name=af-south-1 --set region.role=edge \
  --set config.baseURL=https://hooks-af.example.com
```

An edge release does not render a dispatcher **at all** — not scaled to zero,
absent. A Deployment with `replicas: 0` is one `kubectl scale` away from being
the second dispatcher that silently breaks ordering, and the person who runs
that command will be under pressure and looking for capacity.

The server refuses to start a dispatcher in an edge region for the same
reason, which is the belt to the chart's braces. Ordering is enforced by a
database claim, and a claim only serialises against claimants reading the same
rows — a second dispatching region delivers the same events twice, out of
order, and nothing errors while it happens.

**Failover is a human decision.** See
[the runbook](../docs/runbook-failover.md). An automated promotion on a
network partition produces two primaries, and a false-positive failover is
worse than the outage it responds to.

```bash
statushubctl doctor --replication   # run against the replica, before promoting
```

## The partition job is not optional

`raw_events` is partitioned monthly and nothing else creates the partitions.
The chart installs a daily CronJob that provisions three months ahead, so it
can be broken for two of them without harm — and it recovers rows that landed
in the catch-all while it was, which is what stops a missed run becoming
permanent.

Without it, events still arrive and are still stored, in the default
partition, where retention can never drop them. The symptom is a disk that
fills six months later.
