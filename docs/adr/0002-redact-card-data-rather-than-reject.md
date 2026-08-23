# ADR-002: Redact card data rather than reject the payload

**Status:** Accepted
**Date:** 2026-08-23

## Context

StatusHub never collects card data, and being out of PCI-DSS scope is a
stated part of the product (§8.4, §9). That only holds if a provider putting a
full PAN into a webhook — usually by accident, usually in a narration or
description field — cannot drag every backup, replica and log index into scope
behind it.

§8.4 describes the control as rejecting any payload containing a 13–19 digit
string that passes a Luhn check. §10 describes it as detecting the pattern and
redacting before storage. Both are in the specification; they are different
behaviours and only one can be implemented.

## Decision

Detect and redact. The payload is stored with each card-number-shaped value
replaced by a fixed-length placeholder, the raw event is flagged `redacted`,
and the customer is told through the forwarded event.

Signature verification runs against the original bytes, before redaction. Only
what is stored is altered.

`body_sha256` is computed over the original bytes too, so it remains the
deduplication key for providers that supply no event ID, and remains proof of
what arrived even though what arrived is no longer retained in full.

## Why not reject

Rejecting means a 4xx to the provider. The provider exhausts its retries
against that 4xx and stops, and the event is gone — there is no copy anywhere,
because refusing it is precisely a decision not to keep one.

That trades a recoverable problem for an unrecoverable one. A redacted field
inside `provider_extra` costs a debugging session. A rejected payment
notification costs a payment that the fintech's ledger never learns about, on
a transaction that really happened, with no record that anything was missed.

Every other design decision in this system is arranged so that no provider
event is ever lost (ADR-001). Rejecting a real payment to avoid storing a card
number the provider should not have sent would be the one place we chose
otherwise, and it would be the wrong place.

## Consequences

- A redacted raw event can no longer be re-verified against its signature. It
  was verified on the request path against the original bytes, and the result
  is recorded — re-verification later was never a control we relied on.
- The redaction is not silent: it increments a counter labelled by provider,
  logs at warn, and is visible on the event. A provider that starts sending
  card data is a conversation to have with that provider, and the operator has
  to be able to see it starting.
- Luhn is required in addition to the digit-length test. Length alone matches
  NIP session identifiers, numeric merchant references and account numbers,
  and redacting those would destroy the fields the product exists to correlate
  on. Luhn's roughly one-in-ten false-positive rate on random digit strings is
  acceptable precisely because the outcome is a replacement rather than a
  rejection.
