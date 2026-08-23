# ADR-006: Receivers in every region, dispatchers in exactly one

**Status:** Accepted
**Date:** 2026-08-23

## Context

A provider POSTing from Lagos to a receiver in Frankfurt pays 90–150 ms of
round trip before StatusHub does any work at all. The receiver's budget is
50 ms (§11.3) and it is spent almost entirely on one INSERT, so the network is
not competing with the work — it dwarfs it.

That is an argument for putting receivers close to the providers. It is not,
on its own, an argument for putting *everything* close to them, and the
difference is where every multi-region webhook system goes wrong.

## What actually forces the shape

Three facts, and they point in different directions:

1. **The receiver must be near the provider.** A provider that times out
   retries, and a provider that exhausts its retries loses the event
   permanently. Latency here is not a comfort question.

2. **Ordering is enforced by a database claim.** The dispatcher's guarantee —
   at most one in-flight delivery per `(destination, transaction_ref)` — is a
   `DISTINCT ON … FOR UPDATE SKIP LOCKED` against one table (ADR-003). It
   holds because every claimant reads the same rows under the same locks.

3. **Multi-primary Postgres does not give you that.** Whatever the replication
   topology, two primaries accepting writes cannot serialise a claim between
   them without a consensus round trip that costs more than the ordering is
   worth — and a topology that resolves conflicts *after the fact* has already
   delivered both events.

## Decision

**Receivers run in every region. The dispatcher, the normaliser and the
management API run in exactly one.**

```
  eu-west-1                    us-east-1  (primary)
  ┌──────────────┐             ┌──────────────────────────┐
  │ receiver ×N  │────────────▶│ Postgres primary         │
  └──────────────┘   writes    │                          │
                               │ dispatcher · normaliser  │
  af-south-1                   │ api · dashboard          │
  ┌──────────────┐             └──────────────────────────┘
  │ receiver ×N  │────────────▶            ▲
  └──────────────┘   writes                │ streaming replication
                               ┌───────────┴──────────────┐
                               │ Postgres replica (warm)  │
                               └──────────────────────────┘
```

Receivers do one thing: verify, INSERT, answer 200. That INSERT crosses
regions, and it is one round trip against a primary rather than a
consensus protocol — 30–80 ms typically, which fits the budget when the
alternative is 150 ms of provider round trip *plus* the write.

Everything that reads-then-writes stays in one place, where the claim query
means what it says.

## Why not the obvious alternatives

**Regional queues, drained centrally.** The receiver writes locally and
something ships events to the primary. This is genuinely faster for the
provider, and it moves the durability boundary: the 200 now means "written
somewhere regional", and a region lost before the drain loses events that were
acknowledged. The whole product rests on the acknowledgement being backed by
durable central storage (ADR-001), so this trades away the one guarantee
everything else is built on.

**Active-active with conflict resolution.** Two primaries, both accepting
deliveries, reconciling afterwards. "Afterwards" is the problem: by the time a
conflict is detected, both regions have already POSTed the event to the
customer, and no amount of reconciliation un-sends an HTTP request.

**A dispatcher per region, partitioned by shard.** Region A owns shards 0–31,
region B owns 32–63. This is correct — the shard is the ordering unit, so
disjoint shard sets cannot conflict. It is not adopted because a region
failure then strands its shards until somebody reassigns them, and the
reassignment is exactly the split-brain decision the design was avoiding.
Worth revisiting if delivery throughput ever becomes the constraint; it is
not, because delivery is network-bound on the customer's endpoint.

## Failover

Promoting the replica is a deliberate, human act. It is not automated, and
that is the decision worth defending.

An automated failover on a network partition promotes a second primary while
the first is still accepting writes and still dispatching. Two dispatchers
claiming from two primaries deliver the same events twice, in the wrong order,
and the ordering guarantee — the thing customers integrate against — is gone
for the duration. A false-positive failover is worse than the outage it
responds to.

What is automated is everything that makes the human decision fast:

- Receivers keep accepting during a primary outage only for as long as their
  connection pool holds. Once the primary is unreachable they return **503**,
  which is correct: a provider retrying is far better than a provider being
  told we stored something we did not.
- `statushubctl doctor --region` reports replica lag, so the operator knows
  what promoting will cost before they do it.
- The dispatcher is a separate Deployment with `replicas: 0` in every
  secondary region, so promoting is scaling one Deployment up after scaling
  the other down — an ordering a runbook can state and a human can verify.

## Consequences

- **The receiver's write is cross-region.** Budgeted for: the ceiling is
  `STATUSHUB_DB_WRITE_BUDGET`, and exceeding it raises the existing latency
  alert rather than a new one nobody has seen before.
- **Read replicas serve nothing.** The event explorer reads the primary. A
  dashboard that showed an event as undelivered because it read a lagging
  replica would send an operator to replay something already delivered.
- **`statushub_region` labels every metric**, so a regional problem is visible
  as one rather than as a global degradation nobody can locate.
- **Runbook 11.9** covers promotion, and its first step is confirming the old
  primary is genuinely gone rather than merely unreachable.
