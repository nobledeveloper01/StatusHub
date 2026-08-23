# ADR-005: A destination-wide outage parks deliveries; it does not spend their retry budget

**Status:** Accepted
**Date:** 2026-08-23

## Context

A retry budget answers one question: how long do we keep trying *this event*
against a working destination? Seven attempts over nine hours, then the
dead-letter queue, so that one bad event cannot block its transaction's
ordering key forever (ADR-003).

That reasoning does not transfer to a destination that is down entirely. The
event is fine. Every event is fine. What is broken is the endpoint, and every
queued event is burning its budget against it simultaneously.

Left alone, a nine-hour outage dead-letters everything queued during it — and
does so at the moment the customer's service comes back, because that is when
the last attempts land. The customer recovers their endpoint and immediately
discovers a dead-letter queue with a day of payments in it that somebody now
has to find and replay by hand.

## Decision

While a destination's circuit breaker is open, a delivery that would have
dead-lettered is **parked** instead: its attempt counter is rolled back and it
is rescheduled, up to a bounded outage window of 24 hours.

The retry budget still governs the case it was designed for — a specific event
failing against a healthy destination. It simply no longer governs the case it
was never about.

## Why the window is bounded

Parking without a limit means a destination that was decommissioned without
anybody telling us accumulates a queue forever, invisibly. Twenty-four hours
is long enough to cover an outage that starts on a Friday evening and is fixed
on Saturday morning, and short enough that a genuinely dead endpoint produces
visible dead letters within a day.

Past the window the conclusion changes: the destination is not having an
outage, it is gone, and the events belong somewhere an operator will see them.

## Consequences

- The breaker's failure threshold must sit below the retry budget, or the
  breaker opens only after the event it was meant to protect has already
  dead-lettered. The shipped defaults hold that relationship — five
  consecutive failures against a seven-attempt schedule — and it is asserted
  in the tests rather than left as a coincidence.
- A parked delivery is `failed` with a short retry, not `in_flight`, so it
  does not hold its transaction's ordering key against other work.
- `statushub_deliveries_total{status="parked"}` distinguishes parked from
  retrying, so a dashboard does not show an outage as a rising failure rate.
- Only transport failures, 5xx and 429 feed the breaker. A 400 is about one
  payload, and counting it would trip the breaker for every other event
  because one was malformed.
