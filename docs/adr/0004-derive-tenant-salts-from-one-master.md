# ADR-004: Derive per-tenant salts rather than provisioning them

**Status:** Accepted
**Date:** 2026-08-23

## Context

Customer identifiers — an email, an account name — are hashed before storage
with a salt that is per tenant, so that one tenant's leaked data cannot
correlate a person across another's (§8.4).

The obvious implementation is a salt per tenant, provisioned at tenant
creation and stored in the secret manager. That is what the first version did,
and running the product end to end for the first time found the problem with
it immediately.

## The failure it produced

A tenant whose salt had not been provisioned did not error. The normaliser
resolved the reference, got nothing, dropped the customer identifier — which
is the correct safe behaviour, since the alternative is storing it in the
clear — and flagged the event `mapping_complete: false`.

So: every event processed, every event forwarded, nothing logged above warn,
no alert, and every customer reference silently absent. The only symptom was a
flag on a dashboard nobody had a reason to open, on a screen that exists for
an entirely different purpose.

A control whose absence is invisible is not a control.

## Decision

One master secret, `STATUSHUB_TENANT_SALT_MASTER`. Each tenant's salt is
derived from it with HKDF-SHA256, using the tenant ID and a versioned purpose
string as the info parameter.

There is no per-tenant provisioning step, so there is nothing to forget.

The properties that mattered are kept:

- **Separation.** Two tenants hashing the same email get different values,
  because the tenant ID is in the derivation.
- **Irreversibility.** A compromised tenant salt does not yield the master,
  so it does not compromise any other tenant.
- **Stability.** The same tenant always derives the same salt. This matters
  more than it looks: a salt that changed would orphan every hash already
  stored, and an erasure request would then match only the events written
  since it changed.

The server refuses to start in the live environment without a master, rather
than warning. The whole point is that the absence must be loud.

## What it costs

Rotating the master re-derives every salt at once, orphaning every stored
hash. Correlation breaks across the rotation boundary and a data subject
erasure would match only half a person's events.

That is worse than rotating a single tenant's salt would have been, and it is
accepted because the rotation is rare and the forgotten-provisioning failure
was routine. `statushubctl secrets` states the consequence in the output
rather than leaving it in a document, and the erasure tooling takes an
explicit salt so a subject request spanning a rotation can still be honoured
against both.

## Consequences

- `statushubctl secrets --for tenant-salt` generates the master and explains
  what losing or replacing it does.
- `Config.Validate` refuses `live` without one.
- The purpose string is versioned (`.../v1/<tenant>`), so a future derivation
  scheme can coexist with this one rather than silently replacing it.
