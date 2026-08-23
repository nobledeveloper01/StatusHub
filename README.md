# StatusHub

**One webhook receiver in front of every payment provider you use.**

Point Paystack, Flutterwave, NIBSS, Monnify, Interswitch and Stripe at
StatusHub instead of at yourself. It verifies each provider's own signature,
normalises wildly different payloads into one canonical transaction schema,
and forwards them to your existing endpoint with ordering, retries and replay
you did not have to build.

The integration is a URL change. Nothing in your codebase changes, except
deleting the per-provider parsing code you no longer need.

```
Paystack ─┐
Flutterwave ─┤                                              ┌─ your ledger
NIBSS ─┤      POST ──▶  StatusHub  ──▶ one payload shape ──▶┤
Monnify ─┤                                                  └─ your analytics
Interswitch ─┤
Stripe ─┘
```

---

## Contents

- [The problem](#the-problem)
- [Quick start](#quick-start)
- [The canonical schema](#the-canonical-schema)
- [Providers](#providers)
- [Adapters for providers we have never heard of](#adapters-for-providers-we-have-never-heard-of)
- [Architecture](#architecture)
- [Delivery: ordering, retries and replay](#delivery-ordering-retries-and-replay)
- [Verifying our signature](#verifying-our-signature)
- [The management API](#the-management-api)
- [Running it](#running-it)
- [Security posture](#security-posture)
- [Operations](#operations)
- [Runbooks](#runbooks)
- [Development](#development)
- [Design decisions worth reading](#design-decisions-worth-reading)
- [Roadmap](#roadmap)
- [Licence](#licence)

---

## The problem

A fintech integrates three to five providers. Each delivers webhooks
differently, and the differences are not cosmetic.

| | What varies |
|---|---|
| **Payload shape** | `data.status` vs `event.payment.state` vs `Status` |
| **Amount units** | Kobo, naira, decimal strings, integer minor units — sometimes inconsistently within one provider |
| **Success value** | `"success"`, `"successful"`, `"SUCCESS"`, `"00"`, `"completed"`, `true` |
| **Signature scheme** | HMAC-SHA512 over the raw body; HMAC-SHA256 over a concatenation of named fields; a shared secret echoed in a header; IP allowlist only |
| **Timestamps** | ISO 8601 UTC; ISO with offset; Unix seconds; `"2026-08-11 09:14:22"` with an unstated timezone |
| **Retry policy** | Three attempts over ten minutes; ten over 24 hours; none at all |

So the webhook handler becomes a 600-line switch on provider name that exactly
one engineer understands, and that engineer eventually leaves. When it returns
a 500, some providers retry and some do not. Provider retries are exhausted
long before an outage is fixed, and those events are simply gone.

**What changes with StatusHub**

| | Before | After |
|---|---|---|
| Time to integrate a new provider | 1–2 weeks | under a day, or zero for a built-in |
| Webhook lines in your codebase | 400–800 | ~40, against one schema |
| Events lost during your deploy | unbounded | zero — buffered and replayable |
| Replaying a historical event | not possible | one API call |
| Signature verification defects | recurring, per provider | centralised, tested once per provider |

---

## Quick start

### Docker Compose — fastest evaluation

```bash
docker compose up
```

That brings up Postgres, the receiver on `:8080`, the dispatcher, and the
management API on `:8081`. Then:

```bash
export STATUSHUB_DATABASE_URL="postgres://statushub:statushub@localhost:5432/statushub?sslmode=disable"
statushubctl init --slug acme --name "Acme Payments" --env test
```

That prints an API key — shown once, stored as an Argon2id hash, never
retrievable. Create a receiver URL and a destination:

```bash
statushubctl endpoints create --tenant acme --provider paystack --env test \
  --secret-ref env://PAYSTACK_TEST --base-url http://localhost:8080
```

```bash
statushubctl destinations create --tenant acme \
  --url https://your-app.example.com/hooks/statushub --secret-ref env://ACME_SIGNING
```

Paste the printed receiver URL into Paystack's dashboard. You are done.

### From a release

Signed binaries for linux and darwin, amd64 and arm64, are attached to every
[release](https://github.com/nobledeveloper01/StatusHub/releases) with
checksums, a cosign signature and an SPDX SBOM.

```bash
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/nobledeveloper01/StatusHub/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Keyless: there is no public key to fetch, because the signature attests to the
workflow, repository and tag that produced the file. That attestation is what
you actually want to check.

### From source

```bash
go install github.com/nobledeveloper01/StatusHub/cmd/statushub@latest
```

```bash
statushub serve --mode all --store memory
```

The memory store needs no database and is enough to see the whole flow. It is
refused in the live environment, because a webhook receiver that loses events
on restart is the one thing this product exists not to be.

---

## The canonical schema

This is what your handler receives, whichever provider sent the event. You
write it once and never touch it again when a new provider is added.

```json
{
  "event_id": "sh_evt_06G2R1RMDNS3N9PR5X2XGSDY9G",
  "event_type": "payment.completed",
  "provider": "paystack",
  "provider_event_id": "evt_88213",
  "transaction_ref": "TXN-2026-08-11-8842",
  "status": "success",
  "amount_minor": 5000000,
  "currency": "NGN",
  "occurred_at": "2026-08-11T09:14:31Z",
  "received_at": "2026-08-11T09:14:31.204Z",
  "customer": { "ref_hash": "sha256:…" },
  "provider_extra": { "data.channel": "card", "data.fees": 7500 },
  "mapping_complete": true
}
```

**The guarantees, stated plainly:**

- `amount_minor` is **always** integer minor units, in the currency's own
  exponent. Kobo for NGN, cents for USD, yen for JPY — never a float, never a
  decimal string, never a unit you have to look up.
- `occurred_at` is **always** RFC 3339 UTC.
- `status` is **always** one of six values: `pending`, `success`, `failed`,
  `reversed`, `abandoned`, `unknown`.
- `provider_extra` carries **every field the mapping did not claim**. Nothing
  a provider sent is ever dropped.
- `mapping_complete` tells you when StatusHub is unsure.

### `unknown` is a first-class status

The tempting default for an unrecognised provider status is `failed`, because
failure looks like the safe option. It is not. A fintech that treats an
unmapped `SUCCESS` as a failure reverses a payment that actually completed,
and the customer is charged for a refund of money they received.

So StatusHub never guesses. An unrecognised value becomes `unknown`, the
provider's own string is preserved in `unmapped_status`, and it raises
`statushub_status_unknown_total{raw_value}` — a live feed of exactly which
provider values need mapping. The product tells you what to build next instead
of waiting for a customer to report it.

`GET /v1/unknown-statuses` is that list, ranked by frequency.

---

## Providers

Six built-in adapters. Each documents its own signature scheme, its status
mapping, and — where it applies — the ways in which it is weaker than the
others.

| Provider | Signature | Amounts | Event ID | Note |
|---|---|---|---|---|
| **Paystack** | HMAC-SHA512 hex over the raw body | minor | none | Deduplication falls back to the body hash. Dispute events carry the disputed transaction's reference one level deeper. |
| **Flutterwave** | Shared secret echoed in `verif-hash` | major | `data.id` | **The header does not cover the body**, so it cannot detect a modified payload. Replay is contained by deduplication and the unguessable receiver token, not by the header. |
| **NIBSS NIP** | HMAC-SHA256 over `sessionId+paymentReference+amount`, plus a source-address check | major | `sessionId` | **The signature covers three fields, not the payload**, so the response code itself is unauthenticated. Codes 91, 96 and 97 map to `pending`, not `failed`. |
| **Monnify** | HMAC-SHA512 hex over the raw body | major | `transactionReference` | `PARTIALLY_PAID` maps to `unknown` deliberately — see below. |
| **Interswitch** | HMAC-SHA256 base64 over `transactionRef+amount+responseCode` | minor | `transactionRef` | The response code *is* signed, so the outcome cannot be altered without invalidating the signature. Currency arrives as an ISO 4217 numeric code and is converted. |
| **Stripe** | HMAC-SHA256 over `{timestamp}.{body}`, five-minute window | minor | `id` | The strongest of the six, and the scheme StatusHub copies for its own outbound signatures. Put your reference in `metadata.transaction_ref`. |

`statushubctl adapters list` prints this, and `adapters describe --name X`
prints the full status mapping.

### Two mappings worth explaining

**Monnify `PARTIALLY_PAID` → `unknown`.** A part payment is not a success and
not a failure: the money is real and the obligation is not discharged. The
canonical enum has no value for that, and both approximations cost money —
`success` credits an invoice that was not paid, `failed` discards a payment
that was. `unknown` says exactly what is true, and `amount_minor` carries what
actually arrived so your own logic can compare it against what you expected.

**NIBSS codes 91, 96, 97 → `pending`.** Those mean the beneficiary bank was
unavailable, the system malfunctioned, or the request timed out. The transfer
is still in flight. Mapping them to `failed` is how a fintech reverses money
that later settles.

---

## Adapters for providers we have never heard of

Adapters are configuration, not code. That is what turns StatusHub from a
service into a platform: you can support a provider we have never seen without
opening a support ticket or waiting for a release.

```json
{
  "name": "acme-bank",
  "version": 1,
  "verification": {
    "type": "hmac",
    "algorithm": "sha512",
    "source": "raw_body",
    "header": "x-acme-signature",
    "encoding": "hex"
  },
  "mapping": {
    "provider_event_id": "$.eventId",
    "transaction_ref": "$.data.reference",
    "occurred_at": {
      "path": "$.data.paidAt",
      "format": "2006-01-02 15:04:05",
      "timezone": "Africa/Lagos"
    },
    "amount": {
      "path": "$.data.amount",
      "unit": "major",
      "currency_path": "$.data.currency"
    },
    "status": {
      "path": "$.data.status",
      "values": { "00": "success", "SUCCESSFUL": "success", "PENDING": "pending", "FAILED": "failed" },
      "default": "unknown"
    }
  }
}
```

Test it against real captured payloads before it goes anywhere near live
traffic:

```bash
statushubctl adapters test --config acme-bank.json --sample captured-success.json --sample captured-failure.json
```

The dry run's real output is the **warnings**, not the green tick:

```
no provider_event_id is mapped, so deduplication falls back to hashing the body.
these status values appeared in the samples with no mapping and would become unknown: SETTLING
no timestamp header is configured, so a captured request stays replayable indefinitely.
```

**Rules the validator enforces, and why:**

| Rule | Because |
|---|---|
| `amount.unit` must be stated | Guessing is a hundredfold error in someone's ledger. There is no safe default, so there is no default. |
| A zone-free timestamp format must state a `timezone` | Read as UTC, a Lagos timestamp places the event an hour before it happened, which reorders it against everything else on the transaction. |
| `status.default` may only be `unknown` | An adapter that could default to `failed` would eventually reverse a payment that succeeded. It is not configurable. |
| Only object access and array indexing in paths | An uploaded adapter is customer data running on the normalisation path. Wildcards, recursive descent and filters are a denial of service delivered through a configuration form. |
| Unknown configuration fields are rejected | Someone who typed `transactionRef` instead of `transaction_ref` should be told, not have every event silently flagged incomplete. |
| A built-in adapter's name cannot be redefined | |

---

## Architecture

```
Provider POST arrives
  ├─ verify signature             secret held in memory, constant-time compare
  ├─ write raw event to store     one INSERT, durable
  ├─ RETURN 200 to the provider   ← the provider is now satisfied
  └─ enqueue for normalisation    async, off the request path
```

**Persist, then acknowledge, then process.** This ordering is the whole
design, and the two alternatives are both wrong:

- **Normalise before acknowledging** and a provider's field rename causes a
  500, so the provider retries, and each retry fails identically — producing a
  growing backlog of events that will never parse, duplicated as many times as
  the retry budget allows. Under the accepted ordering the same change is a
  warning on a dashboard: the bytes are already stored, the adapter is
  corrected, and the window is replayed. Runbook, not incident.
- **Acknowledge before persisting** and a crash in that window loses the event
  permanently, with no record it ever arrived. Every other loss in this system
  is recoverable; that one is not.

The full argument, with the alternatives written out, is
[ADR-001](docs/adr/0001-persist-then-acknowledge.md).

### Two workloads, deployed separately

| Workload | Profile | Scales on | Ready means |
|---|---|---|---|
| `--mode receiver` | Latency-critical, high connection count | requests/sec and p99 | it can write to the raw event store |
| `--mode dispatcher` | Throughput-oriented, network-bound | pending queue depth | it can read the store and reach the network |

**The receiver stays available when the dispatcher is entirely down.** That is
the point of persist-then-acknowledge, and it is why the two have different
readiness definitions — a shared probe would take the receiver out of rotation
for a dispatcher fault, losing precisely the events the design exists to
protect.

### Repository layout

```
cmd/statushub/          server binary — receiver, dispatcher, api, or all
cmd/statushubctl/       admin CLI, including `doctor`
internal/domain/        canonical schema, status enum, amounts, audit records
internal/adapter/       what a provider integration must do; HMAC + time primitives
internal/adapters/      the six built-ins, the declarative adapter, the registry
internal/jsonpath/      the deliberately small, bounded expression subset
internal/receive/       HTTP receiver — verify, persist, acknowledge
internal/normalise/     raw bytes → canonical events, off the request path
internal/dispatch/      sharded ordered delivery, retries, DLQ, replay, SSRF guard
internal/store/         Postgres and in-memory implementations of one interface
internal/api/           the management API
internal/auth/          API keys, roles, the authenticated identity
internal/redact/        card data removed before storage
internal/secret/        secret references resolved at use, never stored
internal/metrics/       the Prometheus surface
migrations/             reviewed separately from code, embedded into the binary
docs/adr/               the decisions worth defending
tests/                  the whole suite, against the exported API only
```

---

## Delivery: ordering, retries and replay

### Ordering per transaction, parallelism across them

A `success` that arrives before the `pending` that preceded it corrupts your
state machine. So events sharing a `transaction_ref` are hashed onto the same
shard and delivered **sequentially**; different references proceed in
parallel.

Sequence numbers are allocated at enqueue, not at delivery — a delivery that
fails and waits six hours keeps its position, so an event queued after it
cannot overtake it.

**Head-of-line blocking is bounded, on purpose.** A destination failing on one
specific event blocks that transaction for as long as the retry budget lasts.
Skipping past it would deliver `success` while `pending` is still queued,
which is the corruption ordering exists to prevent. But once the budget is
spent the delivery dead-letters and the key unblocks immediately — otherwise
one unreachable endpoint stalls a shard forever. The bound is visible as
`statushub_shard_oldest_pending_seconds` and pages at fifteen minutes.
[ADR-003](docs/adr/0003-ordering-with-a-bounded-blocking-window.md).

### The retry schedule

`0s, 10s, 1m, 5m, 30m, 2h, 6h` — roughly nine hours, with jitter, then the
dead-letter queue. Configurable per destination.

Jitter is not cosmetic: without it a destination that recovers after a
thirty-minute outage is hit by every pending delivery in the same instant.

**What retries and what does not.** The dividing line is whether repeating the
request could plausibly work. A 5xx, a timeout, a 408 or a 429 could. A 400
saying the payload is malformed will say the same thing in six hours, so
retrying only delays the dead letter an operator needs to see.

A redirect is never followed: replaying a signed POST to a location you never
registered is an SSRF primitive handed over willingly.

### Replay

```bash
# See the size of the window before committing to it — always do this first
curl -X POST $API/v1/events/replay \
  -H "Authorization: Bearer $KEY" \
  -d '{"provider":"paystack","from":"2026-08-11T00:00:00Z","dry_run":true}'
```

Replayed deliveries carry `X-StatusHub-Replay: true` and the **same**
`Idempotency-Key`, so a handler that already processed the event recognises
it. Destination filters still apply — a replay that ignored them would send an
analytics sink the pending events it deliberately excluded.

Retrying a dead letter creates a *new* delivery. The dead letter is evidence
of what the destination said and when; overwriting it to try again would
destroy the record of the failure that prompted the retry.

---

## Developing against it

Two commands remove the worst parts of a webhook integration.

**Live events on your laptop, no public URL:**

```bash
statushubctl listen --forward http://localhost:3000/hooks --key sh_test_...
```

Real events stream to your machine with the same payload and the same
signature production receives, so your verification code is exercised rather
than skipped. Your real destinations keep receiving everything — this is a
copy, never a diversion.

**Prove an integration before a real transaction exists:**

```bash
statushubctl simulate --provider paystack --event charge.success   --url <receiver URL> --secret <the endpoint's secret>
```

The samples are the same captured payloads the adapter test suite runs
against, so a payload the simulator sends is one the adapter is proven to
read. Pass `--all` to include the failure and unmapped-status cases, which are
the ones worth putting through your handler before you rely on it.

**Adopt without a cutover.** Shadow mode forwards each event to your existing
per-provider handler *and* your new canonical one, then reports where they
disagree — and distinguishes the case that is a regression from the case where
your current handler is dropping events today.

## Verifying our signature

The most common way a webhook integration goes wrong is someone writing their
own comparison and making it non-constant-time. So this is the first thing in
the documentation.

```js
import { verifySignature } from '@statushub/node';

app.post('/hooks/statushub', (req, res) => {
  if (!verifySignature(req.rawBody, req.headers['x-statushub-signature'], SECRET)) {
    return res.status(401).end();
  }
  handleEvent(req.body);   // one schema, forever
  res.status(200).end();
});
```

The header is `t=<unix>,v1=<hex>`, an HMAC-SHA256 over `{timestamp}.{body}` —
deliberately Stripe's scheme. It is well documented, widely implemented, and
not a novel cryptographic design invented by a webhook vendor.

Three things matter when you implement it yourself:

1. **Hash the raw bytes**, before any JSON parsing. A round trip through a
   decoder changes them.
2. **Compare in constant time.** `==` on two hex strings leaks the position of
   the first differing byte.
3. **Check the timestamp.** The digest on a captured delivery stays valid
   forever; only the window stops a replay.

During a secret rotation the header carries several `v1=` values — any one
matching is enough, so rotation happens on your schedule rather than requiring
a synchronised cutover.

---

## The management API

Every route is authenticated. Every handler takes its tenant from the
authenticated key, never from the request.

```http
POST   /v1/endpoints                      create a receiver URL
POST   /v1/endpoints/{id}/rotate-token    rotate without changing the URL shape
GET    /v1/endpoints/{id}/signature-failures
POST   /v1/destinations
GET    /v1/adapters                       built-ins and your own, documented
POST   /v1/adapters                       upload a declarative adapter
POST   /v1/adapters/{name}/test           dry run against sample payloads
GET    /v1/events?provider=&status=&transaction_ref=&mapping_complete=&from=&to=&cursor=
GET    /v1/events/{id}                    canonical event + every delivery attempt
GET    /v1/events/{id}/raw                the provider's original bytes (audited)
POST   /v1/events/{id}/replay
POST   /v1/events/replay                  by filter or time range
GET    /v1/deliveries?status=dead_letter
POST   /v1/deliveries/{id}/retry
GET    /v1/unknown-statuses               provider values awaiting mapping
GET    /v1/audit  GET /v1/audit/verify
POST   /v1/keys   GET /v1/keys   DELETE /v1/keys/{id}
GET    /healthz   GET /readyz    GET /metrics
```

**Roles.** `owner` > `engineer` > `support` > `read_only`. The split that
matters is support and engineer: support can search events and replay
deliveries — the things they need hourly — but cannot change an adapter, which
silently alters what every future event from that provider means. Adapter
changes are recorded against the engineer who made them.

**Errors.** A resource belonging to another tenant returns **404, never 403**.
A 403 confirms the resource exists, which is a working cross-tenant
enumeration oracle. Authentication failures all return the same bare 401 —
distinguishing "unknown key" from "revoked key" tells a caller which of their
stolen keys are real.

---

## Running it

### Environment

Every flag has a `STATUSHUB_`-prefixed environment variable.

| Variable | Default | |
|---|---|---|
| `STATUSHUB_MODE` | `all` | `receiver`, `dispatcher`, `api`, or `all` |
| `STATUSHUB_DATABASE_URL` | — | required for the Postgres store |
| `STATUSHUB_STORE` | `postgres` | `memory` is refused in the live environment |
| `STATUSHUB_ENVIRONMENT` | `test` | `live` turns on the strict validations |
| `STATUSHUB_BASE_URL` | `http://localhost:8080` | must be https when live |
| `STATUSHUB_LISTEN_ADDR` | `:8080` | |
| `STATUSHUB_API_LISTEN_ADDR` | `:8081` | |
| `STATUSHUB_SHARDS` | `64` | changing this is a migration, not a tweak |
| `STATUSHUB_TRUST_PROXY_HEADERS` | `false` | only behind a proxy you control |
| `STATUSHUB_BLOCKED_CIDRS` | — | ranges destinations may never resolve to |
| `STATUSHUB_SHUTDOWN_GRACE` | `30s` | set `terminationGracePeriodSeconds` above this |

Secrets are never stored. The database holds a reference such as
`env://PAYSTACK_LIVE`, and the usable value is resolved at the moment it is
needed. A database dump is not a credential breach.

### Before you go live

```bash
statushubctl doctor --secret-ref env://PAYSTACK_LIVE
```

```
  ok      database               reachable in 5ms
  ok      migrations             up to date
  ok      clock skew             within 475ms of network time
  ok      secret env://…         resolves; 2 values valid, so a rotation overlap is in place
  ok      outbound https         reached https://api.paystack.co
```

Clock skew is checked explicitly because it breaks HMAC timestamp windows in
**both** directions and produces an error message that tells you nothing. It
is a common way an evaluation quietly fails.

---

## Security posture

### What is never collected

| Class | Rule |
|---|---|
| PAN, CVV, full card data, passwords, full BVN | **Never stored.** Any 13–19 digit string passing a Luhn check is replaced before storage, and the redaction is counted, logged and visible on the event. |
| Customer name, email, phone | Hashed with a **per-tenant** salt before storage. HMAC, not a plain digest — a plain SHA-256 of an email is reversible with a wordlist in seconds — and per-tenant, so one tenant's leaked data cannot correlate a person across every other tenant. |
| Raw payloads, references, amounts, statuses | Encrypted at rest; access separately permissioned and independently audited. |

*"We cannot leak what we never collected"* is a far stronger position than
*"we encrypt it well."* PCI-DSS is **out of scope by design**, and that claim
only holds because it is enforced rather than asserted.

### Invalid signatures are stored, flagged, and never forwarded

The two obvious alternatives are both wrong. Discarding a forgery destroys the
forensic trail of an attack in progress. Forwarding it is the vulnerability
itself. Storing-and-flagging gives the security team a complete record of
every forgery attempt while guaranteeing your system never sees one.

`GET /v1/endpoints/{id}/signature-failures` is that record. A spike is a
paging alert, because a burst of forgery attempts against one tenant is
information that tenant needs within minutes.

The 401 returned to the caller says only `signature_verification_failed` —
explaining *why* would turn the endpoint into an oracle a forger can tune
against.

### SSRF: the check that actually holds

Destinations must be HTTPS and must resolve to a publicly routable address.
Both are checked at registration — and again, **inside the dialler**, at
delivery time.

Validating only at registration is defeated by DNS rebinding: an attacker
registers a hostname that resolves publicly long enough to pass the check,
then repoints it at `169.254.169.254` and reads the cloud metadata service's
response out of their delivery log. The delivery-time re-resolution runs after
the lookup the connection will use, so there is no window between checking and
connecting. IPv4-mapped IPv6 is unmapped first, because `::ffff:169.254.169.254`
is the classic bypass.

### Tenancy, in three independent layers

1. **Authentication** — a key resolves to exactly one tenant. No key spans
   tenants.
2. **Query** — every repository method takes `tenantID` as its first argument,
   and no method exists that does not. A forgotten scope is a compile error.
3. **Storage** — Postgres row-level security keyed on a session variable, so
   even a query that forgets to scope returns nothing.

`TestStoreTenantIsolation` and `TestPostgresTenantIsolation` are **blocking CI
gates**. They write every kind of row as tenant A and assert that tenant B
gets `ErrNotFound` — not "forbidden" — from every read.

### The audit trail

Every state change is an immutable record, hash-chained per tenant. Not
promised — enforced:

- The application role has `INSERT` and `SELECT` on the audit table. No
  `UPDATE`, no `DELETE`.
- A `BEFORE UPDATE OR DELETE` trigger raises regardless of role, so even a
  superuser mistake fails loudly. This is asserted in the integration tests.
- Each record's hash covers its content plus its predecessor's, with length
  prefixes so content cannot be shifted across a field boundary undetected.
- A per-tenant gapless sequence, so a *deleted* record is named as a gap
  rather than only detected as a broken hash.
- **Corrections are appended, never applied.** A wrong record is followed by
  one carrying `corrects: <id>`. An audit trail you can edit to fix a mistake
  is one you can edit to hide one.
- `GET /v1/audit/verify` exposes the proof, and returns **409** on a broken
  chain — so anything polling it sees a failure without parsing the body.

---

## Operations

### Metrics

```
statushub_webhooks_received_total{provider,tenant,signature_valid}
statushub_receive_duration_seconds                    # must stay under 50ms p99
statushub_signature_failures_total{provider,source_ip_class}
statushub_normalisation_failures_total{provider,reason}
statushub_mapping_incomplete_total{provider,event_type}
statushub_status_unknown_total{provider,raw_value}
statushub_deliveries_total{destination,status}
statushub_delivery_duration_seconds{destination}
statushub_delivery_queue_depth{shard}
statushub_shard_oldest_pending_seconds{shard}         # head-of-line detection
statushub_dead_letter_total{tenant}
statushub_replay_total{tenant}
statushub_audit_chain_intact{tenant}
```

Source addresses are labelled by *class* (`public_v4`, `private`, `loopback`),
never by value — an address from a scanner is close to unbounded cardinality,
and the label would take the scrape endpoint down during exactly the incident
it exists to surface. The full address is in the log line and the audit
record.

### Service level objectives

| SLI | SLO |
|---|---|
| Receiver availability | 99.99% — a provider that gets a 500 may never retry |
| Receiver p99 latency | < 50 ms |
| Forward success within 6 h | 99.95% |
| Receive-to-forward p99 | < 2 s |

The receiver's target is deliberately higher than the dispatcher's. Losing a
provider event is unrecoverable; delaying a forward is not. Setting one
blanket number for both is the mistake this table exists to avoid.

### Alerts

| Alert | Condition | Severity | First action |
|---|---|---|---|
| Receiver latency | p99 > 200 ms for 2 m | Page | Providers will start retrying — check store write latency |
| Signature failure spike | > 10/min from one source | Page | Forgery attempt, or a provider rotated a secret without telling you |
| Normalisation failures | any, per provider | Warn | The provider changed their payload — runbook below |
| New unknown status | previously unseen `raw_value` | Warn | Map it before it becomes a support ticket |
| Dead letters growing | any increase | Page | Customer endpoint down — customer-impacting |
| Shard stalled | `shard_oldest_pending_seconds` > 900 | Page | Head-of-line blocking — inspect the blocking key |
| Audit chain broken | nightly verification fails | Page | Security incident |

---

## Runbooks

### A provider changed their payload shape

The most common real incident, and the product is designed so it is not an
emergency.

1. **Nothing is lost.** Raw bodies were persisted before normalisation was
   attempted. Confirm that first, then work calmly.
2. Pull the affected events:
   ```bash
   statushubctl events list --tenant acme --provider paystack --mapping-complete=false
   ```
3. Diff the actual payloads against the adapter's expected paths.
4. Correct the adapter and test it against the captured samples:
   ```bash
   statushubctl adapters test --config paystack.json --sample captured.json
   ```
5. Deploy. For a declarative adapter this is a configuration change with no
   code release.
6. Replay the affected window — dry run first.
7. Add the captured samples to the adapter's fixtures, so this specific change
   becomes a permanent regression test.

*"When your provider breaks their contract without telling you, you lose
nothing and recover with two commands."*

### A shard has stalled

1. Identify the shard and its oldest pending delivery.
2. Identify the blocking `transaction_ref` and its destination.
3. Determine whether the destination is failing for **that event
   specifically** — a payload their handler rejects — or **generally**.
4. **Specific:** the retry budget will exhaust and dead-letter it, unblocking
   the shard automatically. Confirm the budget is progressing rather than
   resetting.
5. **General:** every shard will slow. Contact the tenant.
6. To unblock immediately, dead-letter the offending delivery with a recorded
   reason. **Never delete it** — dead-lettering preserves it for replay,
   deleting destroys evidence.

### Backup and recovery

- Postgres with continuous WAL archiving and daily base backups. **RPO 5
  minutes, RTO 1 hour.**
- **Raw events are the irreplaceable asset.** They cannot be regenerated from
  anywhere, because the provider will not resend. They are backed up before
  anything else and restored first.
- Restores are tested monthly into an isolated environment, with a
  verification query that replays a known event end to end.
- Retention: raw events 30 days by default, canonical events 90 days, audit
  records 7 years. Enforced by dropping monthly partitions rather than
  deleting rows.

---

## Development

```bash
make help              # every target, described
make test              # unit tests with the race detector, no database needed
make test-integration  # the full suite, against a real Postgres
make test-isolation    # the tenant isolation gate on its own
make test-adapters     # every adapter against its captured payloads
make test-chaos        # kill components mid-flight; assert nothing is lost
make loadtest          # k6 against a running receiver
make ci                # what CI runs
```

`go test ./tests/...` works on a laptop with nothing installed — the Postgres
tests skip rather than fail. CI always sets `STATUSHUB_TEST_DATABASE_URL`, so
the integration path is never skipped where it matters.

**Testing strategy**

| Layer | Approach |
|---|---|
| Adapter | Every adapter against a corpus of real captured payloads. Every status value in every mapping table has a case. |
| Security | Signature verification against known-good and known-bad vectors per provider. Constant-time comparison asserted, not assumed. |
| Isolation | Two tenants, every read path, 404 rather than 403. Blocking gate. |
| Ordering | Concurrent events sharing a `transaction_ref` must reach the sink in order. |
| Failure | Sink returns 500 → assert the schedule. Sink flaps → assert eventual delivery. Dispatcher dies mid-delivery → assert the lease is reclaimed. |
| Chaos | A dispatcher killed mid-delivery: nothing lost, and every redelivery carries a stable idempotency key. A receiver killed between persist and acknowledge: four provider retries produce one canonical event. The dispatcher entirely absent: the receiver stays ready and keeps accepting. |
| Load | k6 at the §11.9 profile, with the 50 ms p99 encoded as a threshold so the run fails when the SLO is missed. |
| End to end | A signed provider webhook in, one canonical shape out, audit trail complete. |

Tests live in `tests/` rather than beside each package, so they exercise only
the exported API — the same surface a caller gets.

---

## Design decisions worth reading

- **[ADR-001](docs/adr/0001-persist-then-acknowledge.md) — Persist, then
  acknowledge, then process.** Why every other ordering either loses events or
  creates duplicates.
- **[ADR-002](docs/adr/0002-redact-card-data-rather-than-reject.md) — Redact
  card data rather than reject the payload.** Why refusing a payment
  notification to avoid storing a card number the provider should not have
  sent trades a recoverable problem for an unrecoverable one.
- **[ADR-003](docs/adr/0003-ordering-with-a-bounded-blocking-window.md) —
  Per-transaction ordering with a bounded blocking window.** Where ordering
  and throughput are traded off, and why the bound is the retry budget.
- **[ADR-004](docs/adr/0004-derive-tenant-salts-from-one-master.md) — Derive
  per-tenant salts rather than provisioning them.** A control whose absence is
  invisible is not a control: a forgotten salt dropped every customer
  reference silently, and the fix was to remove the step that could be
  forgotten.
- **[ADR-005](docs/adr/0005-park-during-outages-rather-than-dead-letter.md) —
  A destination-wide outage parks deliveries.** Why a retry budget designed
  for one failing event is the wrong instrument for a destination that is
  down, and why the parking window is bounded anyway.

---

## Roadmap

Built and tested:

- [x] Receiver with persist-then-acknowledge, per-provider signature verification
- [x] Six built-in adapters, against captured payloads and signature vectors
- [x] Canonical schema, normalisation engine, `unknown` as a first-class status
- [x] Sharded ordered dispatcher, retries, dead letters, replay
- [x] Declarative adapters with a dry-run test runner
- [x] Management API, API keys with roles, hash-chained audit trail
- [x] Postgres store with row-level security and partitioned raw events
- [x] `statushubctl` — 14 commands, including `doctor`, `listen`, `simulate`,
      `infer`, `partitions`, `usage` and `secrets`
- [x] Embedded dashboard: event explorer, unknown statuses, dead letters,
      endpoints, destinations, adapters, live listeners, audit
- [x] Go, Node and Python client libraries, verified against vectors the
      server itself generates

**Adoption** — the things that get a first event flowing:

- [x] `statushubctl listen` — live events streamed to a handler on your laptop,
      with the same payload and signature production receives. No public URL
      needed.
- [x] `statushubctl simulate` — correctly-signed sample payloads for all six
      providers, from the same corpus the adapter tests run against.
- [x] **Shadow mode** — forwards to your existing handler *and* the new one,
      and reports where they disagree. The objection that actually blocks
      these deals is *"I cannot risk switching my webhook handler"*, and an
      observation period answers it in a way a feature list cannot. It also
      finds bugs in the old handler, which is a conversation worth having
      before anybody blames the new one.
- [x] `statushubctl infer` — drafts a declarative adapter from captured
      payloads, with each guess's reasoning and confidence attached.

**Reliability:**

- [x] Per-destination circuit breaker that parks deliveries instead of
      spending their retry budget ([ADR-005](docs/adr/0005-park-during-outages-rather-than-dead-letter.md))
- [x] Explicit backpressure: per-tenant token bucket, concurrency ceiling,
      `429` with `Retry-After`
- [x] Provider silence detection against each endpoint's own hour-of-week
      baseline
- [x] Partition manager: provisions three months ahead, drops only fully
      expired partitions, recovers rows stranded in the catch-all

**Trust:**

- [x] Idempotency keys on every management write
- [x] Signed audit checkpoints and a nightly chain walk, verifiable by your
      auditor with a public key and without involving us
- [x] Data subject export and erasure, with a verification step
- [x] Usage metering counted from the rows the event explorer shows

**Operability:**

- [x] Alert routing to Slack, email and webhook — pages immediately, warnings
      batched, each carrying its first action
- [x] `statushubctl doctor`
- [x] Canonical schema versioning per destination

**Shipped since:**

- [x] OpenAPI 3.1 at [docs/openapi.yaml](docs/openapi.yaml), generated from the
      route table the router itself is built from, with a CI gate that fails
      when the two disagree
- [x] [Helm chart and Terraform module](deploy/), with the receiver and
      dispatcher as separate workloads and manifests validated against the
      Kubernetes schemas in CI
- [x] Release pipeline: signed multi-platform binaries, SPDX SBOM, cosign
      keyless signing, trivy gate, npm and PyPI publishing on a tag

Still open: multi-region deployment, and Kafka/SQS sink delivery — which §3.3
puts out of scope for v1 deliberately, since it is a different product
decision rather than an unfinished one.

---

## Licence

Business Source License 1.1, converting to Apache-2.0 on 2030-08-23. You may
run StatusHub in production to receive, normalise and forward your own
webhooks or your customers'. You may not offer it to third parties as a hosted
webhook service.

The client libraries in `sdk/` and `pkg/statushub` are Apache-2.0, so
integrating needs no lawyer.
