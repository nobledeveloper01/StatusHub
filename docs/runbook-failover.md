# Runbook: promoting a replica

**This is a human decision. Nothing automates it, on purpose.**

An automated failover on a network partition promotes a second primary while
the first is still accepting writes and still dispatching. Two dispatchers
claiming from two primaries deliver the same events twice, in the wrong order,
and the ordering guarantee customers integrate against is gone for the
duration. A false-positive failover is worse than the outage it responds to.

## Before anything

**1. Establish that the primary is gone, not merely unreachable from here.**

```bash
statushubctl doctor --skip-egress          # from a third location, not the replica
kubectl --context primary get pods -l app.kubernetes.io/name=statushub
```

Unreachable from your laptop is not gone. Unreachable from the replica's
region is not gone either — that is the partition case, and it is the one that
produces two primaries.

**2. Find out what promoting costs.**

```bash
statushubctl doctor --replication          # run this AGAINST THE REPLICA
```

Read the assessment, not the number:

| | |
|---|---|
| `stream healthy, N ms behind` | Safe, if the primary is genuinely gone. |
| `N behind. Wait if the primary might come back` | You lose that window of events. They are not recoverable — the provider will not resend. |
| `the WAL stream is not connected` | **Stop.** The lag figure is stale and the true gap is unknown. Find out why replication stopped before promoting anything. |
| `this is the primary, not a replica` | You are on the wrong host. |

## What is happening while you decide

Edge receivers keep accepting only while their connection pool holds. Once the
primary is unreachable they return **503**, and that is correct: a provider
retrying is far better than a provider being told we stored something we did
not.

Providers retry on 503 for hours. The clock you are working against is their
retry budget, not your own patience — check the adapter table in the README
for how long each one gives you.

## Promoting

**Order matters. Scale down before scaling up.**

```bash
# 1. Stop the old dispatcher, if the old primary is reachable at all.
#    A dispatcher that comes back after you promote is the split brain.
kubectl --context old-primary scale deploy/statushub-dispatcher --replicas=0

# 2. Promote the database.
aws rds promote-read-replica --db-instance-identifier acme-statushub-replica

# 3. Point the deployment at it and give it the primary role.
helm --kube-context new-primary upgrade statushub deploy/helm/statushub \
  --set region.name=eu-west-1 \
  --set region.role=primary \
  --set config.baseURL=https://hooks.example.com \
  --reuse-values

# 4. Repoint the edge regions' database URL at the new primary.
#    They keep role=edge; only the connection string changes.
```

Step 1 is the one people skip. StatusHub refuses to *start* a dispatcher in an
edge region, but it cannot stop one that is already running in a region that
used to be primary.

## Afterwards

```bash
statushubctl doctor --replication          # against the new primary: expect "this is the primary"
statushubctl partitions status             # the daily job runs in the primary; confirm it is here now
statushubctl events list --tenant <slug> --from <the outage window>
```

**Check the audit chain.** A promotion that lost transactions leaves a gap,
and the chain walk names it as a gap rather than as a vague inconsistency:

```bash
curl -H "Authorization: Bearer $KEY" https://api.example.com/v1/audit/verify
```

A 409 here after a promotion is expected if you lost a window of events, and
is not a security incident. Record what was lost, in writing, with the lag
figure you promoted at. That record is what a regulator asks for later, and
reconstructing it from memory in six weeks is not possible.

## What you cannot recover

Events the provider delivered into the lost window. StatusHub acknowledged
them, so the provider will not resend, and they were never replicated. This is
the one unrecoverable loss in the system and it is why:

- `backup_retention_period` gives point-in-time recovery to 5 minutes (§11.7),
- the replica is warm rather than a nightly restore,
- and the assessment above states the cost in events rather than in seconds.

If the window matters, the recovery is a point-in-time restore of the old
primary rather than a promotion — slower, and it loses nothing.
