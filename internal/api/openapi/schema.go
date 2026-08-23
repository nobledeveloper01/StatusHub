package openapi

import "fmt"

// header is the document preamble.
//
// The prose here is the part a generator cannot produce and the part an
// integrator actually reads. A schema tells them `status` is a string; only a
// sentence tells them that `unknown` means StatusHub refused to guess and
// that treating it as a failure will reverse payments that succeeded.
func header(version string) string {
	return fmt.Sprintf(`# Generated from the router. Do not edit by hand.
#
# Regenerate with:  go run ./cmd/statushubctl openapi > docs/openapi.yaml
#
# CI fails when this file and the routes disagree, because a specification
# maintained beside the code drifts — and a drifted specification is worse
# than none: a generated client calls endpoints that do not exist, omits ones
# that do, and is trusted because it looks authoritative.

openapi: 3.1.0

info:
  title: StatusHub
  version: %q
  summary: One webhook receiver in front of every payment provider.
  description: |
    StatusHub sits between a fintech's payment providers and its own systems.
    It verifies each provider's signature, normalises their wildly different
    payloads into one canonical transaction schema, and forwards them with
    per-transaction ordering, bounded retries and replay.

    ## Two surfaces

    Providers POST to a **receiver URL** that is not described here: it takes
    whatever shape that provider sends, and the only thing a customer does
    with it is paste it into the provider's dashboard.

    This document describes the **management API** — endpoints, destinations,
    adapters, the event explorer and replay.

    ## Authentication

    A bearer API key, formatted %ssh_{env}_{random}%s. A key resolves to exactly
    one tenant and one environment; no key spans either.

    Failures return a bare 401 with no detail. Distinguishing "unknown key"
    from "revoked key" from "wrong environment" would tell a caller which of
    their stolen keys are real.

    A resource belonging to another tenant returns **404, never 403** — a 403
    confirms the resource exists, which is a working cross-tenant enumeration
    oracle. A 403 here means only that your key's role is insufficient for a
    resource that is yours.

    ## Idempotency

    Every write accepts an optional %sIdempotency-Key%s header. A retry carrying
    the same key returns the original result rather than creating a second
    resource, and the reply carries %sIdempotency-Replayed: true%s. Reusing a
    key with a different body is a 409.

    ## The status enum

    %sstatus%s is always one of six values: %spending%s, %ssuccess%s, %sfailed%s,
    %sreversed%s, %sabandoned%s, %sunknown%s.

    **Handle %sunknown%s explicitly.** It means StatusHub did not recognise the
    provider's value and refused to guess. The tempting shortcut is to treat
    it as a failure — that is exactly the mistake it exists to prevent, because
    an unmapped SUCCESS treated as a failure reverses a payment that
    completed. %sunmapped_status%s carries the provider's own string.

  license:
    name: BUSL-1.1
    url: https://github.com/nobledeveloper01/StatusHub/blob/main/LICENSE

servers:
  - url: https://api.statushub.dev
    description: Hosted
  - url: http://localhost:8081
    description: Local, via docker compose

`, version, "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`",
		"`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`")
}

// components holds the shared schemas and responses.
func components() string {
	return `
components:
  securitySchemes:
    apiKey:
      type: http
      scheme: bearer
      description: |
        A key of the form ` + "`sh_live_…`" + ` or ` + "`sh_test_…`" + `. Shown once at
        creation and stored as an Argon2id hash, so it cannot be recovered.

  responses:
    Unauthorised:
      description: |
        The key was not accepted. Deliberately indistinguishable across
        missing, malformed, unknown, revoked, expired and wrong-environment
        keys.
      content:
        application/json:
          example: { "error": "unauthorised" }

    Forbidden:
      description: |
        The key is valid and its role is insufficient. Distinct from 404:
        this resource is yours, and this key may not act on it.
      content:
        application/json:
          example: { "error": "this key has the support role; engineer or higher is required" }

    NotFound:
      description: |
        No such resource — or one belonging to another tenant. The two are
        deliberately identical.
      content:
        application/json:
          example: { "error": "not found" }

  schemas:
    CanonicalEvent:
      type: object
      description: |
        The one shape a destination receives, whichever provider sent the
        event. A customer writes one handler for this and never touches it
        again when a provider is added.
      required: [event_id, event_type, provider, transaction_ref, status, amount_minor, occurred_at, received_at, mapping_complete]
      properties:
        event_id:
          type: string
          description: Also the ` + "`Idempotency-Key`" + ` on the delivery. Deduplicating on it turns our at-least-once into your exactly-once.
        event_type:
          type: string
          enum: [payment.pending, payment.completed, payment.failed, payment.reversed, payment.abandoned,
                 transfer.pending, transfer.completed, transfer.failed, transfer.reversed,
                 refund.completed, refund.failed, chargeback.opened, chargeback.resolved, unknown]
        provider: { type: string, examples: [paystack, flutterwave, nibss, monnify, interswitch, stripe] }
        provider_event_id:
          type: string
          description: The provider's own identifier, where they supply one. Paystack does not.
        transaction_ref:
          type: string
          description: |
            The ordering and correlation key. Events sharing one are delivered
            sequentially; different references proceed in parallel.
        status:
          type: string
          enum: [pending, success, failed, reversed, abandoned, unknown]
        amount_minor:
          type: integer
          format: int64
          description: |
            Always integer minor units, in the currency's own exponent — kobo
            for NGN, cents for USD, yen for JPY. Never a float, never a
            decimal string, never a unit you have to look up.
        currency: { type: string, minLength: 3, maxLength: 3, examples: [NGN] }
        occurred_at: { type: string, format: date-time, description: Always RFC 3339 UTC. }
        received_at: { type: string, format: date-time }
        customer:
          type: object
          description: |
            Pseudonymised. There is no name, email or phone here and there
            never will be — the hash is enough to correlate two events as one
            person without StatusHub holding who that person is.
          properties:
            ref_hash: { type: string, examples: ["sha256:…"] }
        provider_extra:
          type: object
          additionalProperties: true
          description: |
            Every field the mapping did not claim. Nothing a provider sent is
            dropped: a field nobody knew about today is the one somebody needs
            in six weeks.
        mapping_complete:
          type: boolean
          description: |
            False when StatusHub was unsure about a field. Part of the payload
            rather than an internal flag, because a handler that cannot tell
            the difference has been given no way to know.
        unmapped_status:
          type: string
          description: The provider's own string when ` + "`status`" + ` is ` + "`unknown`" + `.
        redacted:
          type: boolean
          description: Card data was found and removed before storage, so the stored original is not byte-exact.

    Error:
      type: object
      required: [error]
      properties:
        error: { type: string }
`
}
