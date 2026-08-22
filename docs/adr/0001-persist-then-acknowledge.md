# ADR-001: Persist, then acknowledge, then process

**Status:** Accepted
**Date:** 2026-08-23

## Context

A provider POSTs a webhook. StatusHub must do four things with it: verify the
signature, store it, normalise it into the canonical schema, and forward it to
the customer's endpoint. Only the ordering of those four is in question, and
the ordering is the whole design.

The provider is not a cooperative partner in this. It has its own retry policy
— three attempts over ten minutes, ten attempts over 24 hours, or none at all
— and it decides whether to retry based on one thing: the status code we
return, and how long we take to return it.

## Decision

```
Provider POST arrives
  ├─ verify signature             secret held in memory
  ├─ write raw event to store     one INSERT, durable
  ├─ RETURN 200 to the provider   ← the provider is now satisfied
  └─ enqueue for normalisation    async, off the request path
```

Normalisation and delivery happen after the response has been written. The
receiver's readiness probe reports healthy as long as it can write to the raw
event store, and says nothing about whether the dispatcher is alive.

## Alternatives rejected

**Normalise before acknowledging.** A provider changes a field name — which
they do, without notice — and normalisation starts failing. Every failure now
returns 500, so the provider retries, and each retry fails the same way. The
result is a growing backlog of events that will never parse, duplicated as
many times as the provider's retry budget allows, and a customer whose
webhooks have stopped for a reason that has nothing to do with their code.

Under the accepted ordering the same provider change is a warning on a
dashboard: the raw bytes are already stored, normalisation is retried against
a corrected adapter, and the affected window is replayed. Runbook 11.5, not an
incident.

**Acknowledge before persisting.** The window between writing the 200 and
committing the row is small and it is fatal. A process killed inside it loses
the event with no record that it ever arrived — the provider believes it
delivered, so it will not retry, and there is nothing to reconcile against
because we never wrote anything down. Every other loss in this system is
recoverable; this one is not.

**Synchronous forwarding.** Ties our availability to the customer's. Their
deploy becomes our 500, which becomes the provider's retry, which becomes our
duplicate.

## Consequences

- We accept at-least-once from the provider and dedupe on
  `(tenant, provider, provider_event_id)`, falling back to a body hash for
  providers that supply no event ID.
- We give at-least-once to the customer, with an `Idempotency-Key` header set
  to the canonical event ID, so their handler can make it exactly-once.
- The receiver and the dispatcher deploy as separate workloads with separate
  readiness definitions. A shared probe would take the receiver out of
  rotation for a dispatcher fault, losing precisely the events this ordering
  exists to protect.
- The receiver's p99 budget is 50 ms, and it is spent almost entirely on one
  INSERT. That is why the raw event table is written to directly rather than
  through any queue that might itself be unavailable.
