# ADR-003: Per-transaction ordering with a bounded blocking window

**Status:** Accepted
**Date:** 2026-08-23

## Context

A fintech's webhook handler is a state machine. A `success` that arrives
before the `pending` that preceded it does not merely arrive out of order — it
moves the transaction to a state the handler then reverses when the `pending`
lands. Ordering is therefore a correctness requirement, not a nicety.

Ordering and throughput are in tension. Strict global ordering means one
delivery at a time per tenant, which will not carry the volume. No ordering
means the state machine corrupts.

## Decision

Order per transaction reference, and only per transaction reference.

Events are hashed onto a fixed number of shards by their transaction
reference, and the store's claim query returns at most one in-flight delivery
per `(destination, transaction reference)`. Two events about one transaction
are therefore never in flight together; events about different transactions
proceed in parallel, bounded only by the shard count and the worker pool.

Sequence numbers are allocated at enqueue time, not at delivery time. A
delivery that fails and waits six hours keeps the position it was given, so an
event queued after it cannot overtake it while it waits.

The shard count is fixed at 64 and changing it is a documented migration
rather than a configuration change. Re-hashing puts a transaction's events on
a different shard from the ones already queued for it, and two events about
one transaction on two shards is exactly the failure the sharding exists to
prevent.

## The blocking window, and why it is bounded

A destination that is failing for one specific event blocks that transaction
reference for as long as the retry budget lasts — about nine hours under the
default schedule. That is head-of-line blocking, and it is deliberate.

The alternative, skipping past a stuck event to deliver the next one for the
same transaction, would deliver `success` while `pending` is still queued,
which is the exact corruption ordering exists to prevent. Blocking is the
correct behaviour.

What is not acceptable is blocking *forever*. When the retry budget is spent,
the delivery moves to the dead-letter queue and the key unblocks immediately.
The bound is therefore the retry budget, it is visible
(`statushub_shard_oldest_pending_seconds`), and it pages at fifteen minutes so
an operator sees it long before it matters.

Choosing a bounded blocking window over unbounded strictness is the trade-off,
and it is worth being able to state which way it goes and why.

## Consequences

- A tenant whose destination is entirely down sees every shard slow, not one.
  That is correct — the problem is global — and the runbook (§11.6)
  distinguishes the two cases as its first diagnostic step.
- A transaction reference that a provider reuses across genuinely unrelated
  payments will serialise them. Documented, and the correct fix is a unique
  reference, which every provider's own documentation also asks for.
- Deliveries are claimed under a lease. A dispatcher that dies mid-delivery
  holds its lease until it expires, after which another replica reclaims the
  work — so a crash costs one lease interval of latency on one key rather than
  a stalled shard.
