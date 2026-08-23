# StatusHub

Universal webhook normaliser for fintechs.

StatusHub sits in front of every payment provider a fintech uses — verifying
each provider's own signature, normalising wildly different payloads into one
canonical transaction schema, and forwarding them to the fintech's existing
endpoint with ordering, retries and replay.

The integration is a URL change. Nothing in the customer's codebase changes,
except deleting the per-provider parsing code they no longer need.

---

## 1. The problem

A fintech of any size integrates three to five providers: Paystack,
Flutterwave, NIBSS, a bank API, perhaps a card processor. Each delivers
webhooks differently, and the differences are not cosmetic.

| | What varies |
|---|---|
| **Payload shape** | `data.status` vs `event.payment.state` vs `Status` |
| **Amount units** | Kobo, naira, decimal strings, integer minor units — sometimes inconsistently within one provider |
| **Success value** | `"success"`, `"successful"`, `"SUCCESS"`, `"00"`, `"completed"`, `true` |
| **Signature scheme** | HMAC-SHA512 over the raw body; HMAC-SHA256 over a concatenation of named fields; a shared secret echoed in a header; IP allowlist only |
| **Timestamps** | ISO 8601 UTC; ISO with offset; Unix seconds; `"2026-08-11 09:14:22"` with an unstated timezone |
| **Retry policy** | Three attempts over ten minutes; ten over 24 hours; none at all |

So the webhook handler becomes a 600-line switch on provider name that exactly
one engineer understands, and that engineer eventually leaves.

The costs compound in a specific order:

> **The handler returns 500. Some providers retry and some do not.**

Transactions get stuck in a state nobody notices until a customer complains.
Provider retries are exhausted long before an outage is fixed, and those
events are simply gone — the provider will not resend, and there is no record
they ever arrived. Reproducing a production webhook bug means asking the
provider to resend, or hand-crafting a payload from memory.

StatusHub is a separate process that receives every provider's webhooks,
stores the bytes before anything tries to understand them, and forwards one
shape.

| | Before | After |
|---|---|---|
| Time to integrate a new provider | 1–2 weeks | under a day, or zero for a built-in |
| Webhook lines in your codebase | 400–800 | ~40, against one schema |
| Events lost during your deploy | unbounded | zero — buffered and replayable |
| Replaying a historical event | not possible | one API call |
| Signature verification defects | recurring, per provider | centralised, tested once per provider |

### What it is not

**StatusHub never decides what a transaction means.** It normalises, forwards
and records; the fintech's own system decides what to do. When a provider
sends a status StatusHub does not recognise, the canonical status is
`unknown` — not a guess — and the customer's code is told plainly that we do
not know.

That boundary is load-bearing. The alternative, mapping an unrecognised
`SUCCESS` to `failed` because failure looks like the safe default, is how a
fintech reverses a payment that actually completed and charges the customer
for a refund of money they received.

**StatusHub is not a payment provider and holds no card data.** Any 13–19
digit string passing a Luhn check is replaced before storage. PCI-DSS is out
of scope by design, and that claim holds because it is enforced rather than
asserted.

---

## 2. How it works

```mermaid
graph LR
    subgraph Providers
        P1[Paystack]
        P2[Flutterwave]
        P3[NIBSS]
        P4[Stripe]
    end

    subgraph SH["StatusHub"]
        RCV[Receiver<br/>verify · persist · ack]
        RAW[(Raw events)]
        NORM[Normalisation<br/>adapter registry]
        CANON[(Canonical events)]
        DISP[Dispatcher<br/>sharded ordered queues]
        DLQ[(Dead letters)]
        EXPL[Event explorer]
    end

    subgraph Customer["Fintech's stack"]
        EP1[Their ledger]
        EP2[Their analytics]
    end

    P1 & P2 & P3 & P4 -->|POST| RCV
    RCV --> RAW
    RCV -->|200 in under 50ms| P1
    RAW --> NORM --> CANON --> DISP
    DISP -->|signed, normalised| EP1
    DISP -->|filtered subset| EP2
    DISP -.retries exhausted.-> DLQ
    RAW & CANON --> EXPL
```

The path an event takes:

1. **Receive** (`POST /v1/hooks/{tenant}/{provider}/{env}/{token}`). Verify
   the provider's signature in constant time, write the raw bytes durably,
   return `200`. Under 50 ms at p99, spent almost entirely on one INSERT.
2. **Normalise** (`internal/normalise`), off the request path. The adapter
   maps the payload onto the canonical schema; the customer identifier is
   hashed with the tenant's salt; unmapped values become `unknown` and raise
   a metric.
3. **Dispatch** (`internal/dispatch`). Events are hashed onto shards by
   transaction reference and delivered sequentially within a reference,
   in parallel across them, signed with the Stripe scheme.
4. **Retry or dead-letter.** `0s, 10s, 1m, 5m, 30m, 2h, 6h` with jitter, then
   the dead-letter queue — which unblocks the transaction's ordering key.

### Persist, then acknowledge, then process

```
Provider POST arrives
  ├─ verify signature             secret held in memory, constant-time compare
  ├─ write raw event to store     one INSERT, durable
  ├─ RETURN 200 to the provider   ← the provider is now satisfied
  └─ enqueue for normalisation    async, off the request path
```

This ordering is the whole design, and the two alternatives are both wrong:

- **Normalise before acknowledging** and a provider's field rename causes a
  500, so the provider retries, and each retry fails identically — producing a
  growing backlog of events that will never parse, duplicated as many times as
  the retry budget allows. Under the accepted ordering the same change is a
  warning on a dashboard: the bytes are already stored, the adapter is
  corrected, the window is replayed. A runbook, not an incident.
- **Acknowledge before persisting** and a crash in that window loses the event
  permanently, with no record it ever arrived. Every other loss in this system
  is recoverable; that one is not.

The full argument is [ADR-001](docs/adr/0001-persist-then-acknowledge.md).

### Event lifecycle

```mermaid
stateDiagram-v2
    [*] --> received: provider POSTs
    received --> stored_unverified: signature invalid
    received --> stored: signature valid
    stored --> normalised: adapter parsed it
    stored --> unparseable: adapter could not read it
    unparseable --> normalised: adapter corrected, window replayed
    normalised --> delivered: destination accepted
    normalised --> retrying: destination failed, budget remains
    retrying --> delivered: a later attempt succeeded
    retrying --> parked: destination is down wholesale
    parked --> delivered: breaker closed, destination back
    retrying --> dead_letter: retry budget exhausted
    dead_letter --> delivered: replayed by an operator
    stored_unverified --> [*]: retained as evidence, never forwarded
    delivered --> [*]
```

Three edges carry most of the product's judgement:

- **`stored_unverified` never leaves.** An event with an invalid signature is
  stored, flagged, and never forwarded. Discarding it would destroy the
  forensic trail of an attack in progress; forwarding it is the vulnerability.
- **`unparseable → normalised`** exists because the raw bytes were persisted
  before anything tried to understand them. A provider changing their payload
  is recoverable rather than fatal.
- **`retrying → parked`** is the circuit breaker. During a destination-wide
  outage a delivery is parked rather than spending its retry budget, so the
  outage does not dead-letter everything queued during it at the moment the
  customer's service comes back
  ([ADR-005](docs/adr/0005-park-during-outages-rather-than-dead-letter.md)).

### The canonical schema

This is what the customer's handler receives, whichever provider sent it:

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

Four guarantees, stated plainly:

- `amount_minor` is **always** integer minor units, in the currency's own
  exponent. Kobo for NGN, cents for USD, yen for JPY — never a float, never a
  decimal string, never a unit you have to look up.
- `occurred_at` is **always** RFC 3339 UTC.
- `status` is **always** one of six: `pending`, `success`, `failed`,
  `reversed`, `abandoned`, `unknown`.
- `provider_extra` carries **every field the mapping did not claim**. Nothing
  a provider sent is ever dropped.

`mapping_complete` tells the customer when StatusHub is unsure. It is part of
the payload rather than an internal flag, because a handler that cannot tell
the difference has been given no way to know.

---
## 3. What each package does

### `internal/domain` — the vocabulary, with no infrastructure

The canonical schema, the status enum, amount arithmetic and the audit record.
No storage, no transport. The question "what did the provider actually tell
us" can be answered and tested without a database.

**`unknown` is a first-class status, not a gap.** The tempting default for an
unrecognised provider value is `failed`, because failure looks like the safe
option. It is not:

```go
// Silently mapping an unrecognised provider status to failed is how a
// fintech reverses a payment that actually succeeded.
StatusUnknown Status = "unknown"
```

`unknown` is also **not terminal**. Not knowing what something is includes not
knowing whether it is finished, and a handler that treats it as terminal stops
watching a transaction that is still moving.

**Amounts never touch a float.** `MajorToMinor` works on the decimal text a
provider sent:

```
8134.55 naira → 813455 kobo
```

Going via `float64` gives `813454.9999999999`, which truncates to a kobo less
than the customer paid — on every transaction, forever. The conversion parses
the digits either side of the point instead. It also **refuses to round**: a
provider sending more precision than the currency has gets an error, because
quietly rounding inside a payment system is how a discrepancy appears in a
reconciliation three months later with no trace of where it came from.

The exponent is per currency. Multiplying by 100 is right for NGN and USD,
wrong for JPY, and wrong in the other direction for the three-decimal Gulf
currencies.

### `internal/adapter` — what a provider integration must do

Three responsibilities, kept separate because they run at different times and
fail differently: `Verify` runs on the request path and must be constant-time,
`Parse` runs afterwards and is allowed to fail without costing the event, and
`DedupeKey` has to work even when parsing does not.

The shared HMAC helpers exist for one reason:

```go
// A `==` on two hex strings leaks the position of the first differing byte
// through timing, and an attacker who can measure that can build a valid
// signature a byte at a time. Doing it once, here, means six adapters cannot
// each get it wrong independently.
func Equal(presented, expected string, enc Encoding) bool
```

Timestamp parsing refuses to guess a timezone. A naive `2026-08-11 09:14:22`
read as UTC when it was written in Lagos places the event an hour before it
happened, which reorders it against every other event on the same transaction.
The zone is stated in configuration or the parse fails.

### `internal/adapters` — six providers, and what each one actually guarantees

| Provider | Signature | Amounts | Event ID |
|---|---|---|---|
| **Paystack** | HMAC-SHA512 hex over the raw body | minor | none |
| **Flutterwave** | Shared secret echoed in `verif-hash` | major | `data.id` |
| **NIBSS NIP** | HMAC-SHA256 over three named fields, plus a source check | major | `sessionId` |
| **Monnify** | HMAC-SHA512 hex over the raw body | major | `transactionReference` |
| **Interswitch** | HMAC-SHA256 base64 over `ref+amount+responseCode` | minor | `transactionRef` |
| **Stripe** | HMAC-SHA256 over `{timestamp}.{body}`, five-minute window | minor | `id` |

Each adapter documents its own weaknesses rather than presenting all six as
equally verified:

- **Flutterwave's header does not cover the body.** A valid header taken from
  any past request authenticates any body at all. Constant-time comparison
  protects the secret from byte-by-byte recovery; it does not make the scheme
  sound. What contains the risk is deduplication on `data.id` and the
  unguessable receiver token.
- **NIBSS signs three fields, not the payload.** The response code — the field
  that says whether the money moved — is not covered. An attacker who reaches
  the endpoint and knows a valid session can alter the outcome without
  invalidating the signature. Interswitch, by contrast, *does* sign the
  response code, which is the difference worth knowing.
- **Stripe is the strongest**, and is the scheme StatusHub copies for its own
  outbound signatures.

Two mappings are worth explaining:

**Monnify `PARTIALLY_PAID` → `unknown`, deliberately.** A part payment is not
a success and not a failure: the money is real and the obligation is not
discharged. The canonical enum has no value for that, and both approximations
cost money — `success` credits an invoice that was not paid, `failed` discards
a payment that was. It is mapped explicitly rather than left to fall through,
so it does **not** raise the new-unknown-status alert: an operator paged about
`PARTIALLY_PAID` every time one arrives learns to ignore the alert, and then
misses the value that genuinely is new.

**NIBSS codes 91, 96 and 97 → `pending`, not `failed`.** They mean the
beneficiary bank was unavailable, the system malfunctioned, or the request
timed out. The transfer is still in flight, and calling it failed is how a
fintech reverses money that later settles.

### `internal/adapters/declarative` — adapters as configuration

What turns StatusHub from a service into a platform: a customer can support a
provider we have never heard of without opening a ticket or waiting for a
release.

```json
{
  "name": "acme-bank",
  "verification": { "type": "hmac", "algorithm": "sha512",
                    "source": "raw_body", "header": "x-acme-signature" },
  "mapping": {
    "transaction_ref": "$.data.reference",
    "occurred_at": { "path": "$.data.paidAt",
                     "format": "2006-01-02 15:04:05", "timezone": "Africa/Lagos" },
    "amount": { "path": "$.data.amount", "unit": "major",
                "currency_path": "$.data.currency" },
    "status": { "path": "$.data.status",
                "values": { "00": "success", "FAILED": "failed" },
                "default": "unknown" }
  }
}
```

It is also the largest attack surface in the product, because it is data an
authenticated customer uploads that then runs on the normalisation path for
every event. So: no scripting of any kind, a
[deliberately small JSONPath subset](#internaljsonpath--a-deliberately-small-subset),
and an explicit ceiling on every list, string and mapping table.

The validation rules each correspond to a way an adapter can be wrong that
would otherwise only surface as corrupted events days later:

| Rule | Because |
|---|---|
| `amount.unit` must be stated | Guessing is a hundredfold error in someone's ledger. No safe default, so no default. |
| A zone-free format must state a `timezone` | An hour's displacement reorders an event against everything else on its transaction. |
| `status.default` may only be `unknown` | An adapter that could default to `failed` will eventually reverse a payment that succeeded. Not configurable. |
| Unknown configuration fields are rejected | Someone who typed `transactionRef` should be told, not have every event silently flagged incomplete. |
| A built-in adapter's name cannot be redefined | |

**The dry run's real output is the warnings, not the green tick.** An adapter
that parses every sample and still has no event ID mapped will duplicate
events on the provider's first retry, and nobody discovers that from a pass.

`statushubctl infer` goes one step earlier: three or four captured payloads
become a draft, with each guess's reasoning and confidence attached. The
amount unit and the timezone are flagged for review by name, because those are
the two guesses that cost money.

### `internal/jsonpath` — a deliberately small subset

Object member access and array indexing. No wildcards, no recursive descent,
no filters, no scripting.

The subset is the point. A declarative adapter is data a customer uploads, and
the moment an expression can backtrack or recurse, it can be made to burn CPU
on the normalisation path — a denial of service delivered through a
configuration form.

Decoding uses `json.Number` throughout. `encoding/json`'s default is `float64`,
which cannot hold every `int64`: an amount of `9007199254740993` comes back as
`…992`. For a transaction amount that is a silent, unrecoverable corruption.

A missing field and an explicit `null` are distinguishable, deliberately. The
first is a mapping problem and the second is information, and collapsing them
loses the difference at the moment it matters.

### `internal/receive` — verify, persist, acknowledge

Does four things and refuses to do a fifth. Everything the customer eventually
sees is produced after the response has been written.

**Invalid signatures are stored, flagged, and never forwarded.** The two
obvious alternatives are both wrong: discarding destroys the forensic trail of
an attack in progress, forwarding is the vulnerability itself. The 401 says
only `signature_verification_failed` — explaining *why* would turn the
endpoint into an oracle a forger can tune against. The operator sees the exact
reason on the signature-failure view.

**Signature headers are stored as `[redacted]`, not omitted.** A stored
signature beside the exact body it signs is a replay kit for anyone who
reaches the database. Recording it as present-and-redacted lets an
investigator tell a request that carried no signature from one whose signature
we chose not to keep.

**The body cap is enforced by reading one byte past it**, rather than by
trusting `Content-Length`, which is a claim the caller makes.

Rotation works because verification tries every currently-valid secret. A
secret swapped atomically rejects every in-flight event signed with the old
one, which turns a routine rotation into lost webhooks.

### `internal/redact` — card data, removed before storage

Any 13–19 digit run passing a Luhn check is replaced before the bytes are
written. Verification runs against the *original* bytes; only what is stored
is altered.

Luhn is required in addition to the length test. Length alone eats NIP session
identifiers, numeric merchant references and account numbers — the exact
fields the product exists to correlate on. Luhn's roughly one-in-ten
false-positive rate on random digit strings is acceptable precisely because
the outcome is a replacement rather than a rejection.

Redaction rather than rejection is [ADR-002](docs/adr/0002-redact-card-data-rather-than-reject.md).
Refusing the payload means a 4xx, an exhausted provider retry budget, and a
real payment nobody has a record of — trading a recoverable problem for an
unrecoverable one.

### `internal/normalise` — raw bytes to canonical events

Runs entirely off the request path, which is what makes every failure in here
recoverable.

Customer identifiers are hashed here, with the tenant's salt, and the
plaintext is discarded. HMAC rather than a plain digest — a plain SHA-256 of
an email is reversible with a wordlist in seconds — and per tenant, so one
tenant's leaked data cannot correlate a person across another's. **The adapter
never sees the salt**, so no adapter can accidentally write an identifier in
the clear.

The salt is derived from one master rather than provisioned per tenant
([ADR-004](docs/adr/0004-derive-tenant-salts-from-one-master.md)). Per-tenant
provisioning has a failure mode that is quiet and total: a tenant whose salt
was never created has every customer reference silently dropped, nothing
errors, and the only symptom is a flag on a screen nobody has a reason to
open.

### `internal/dispatch` — ordering, retries, and not being an SSRF pivot

**Per-transaction ordering with parallelism across transactions.** A `success`
arriving before the `pending` that preceded it corrupts the customer's state
machine, so events sharing a `transaction_ref` are hashed onto one shard and
delivered sequentially. Different references proceed in parallel.

Sequence numbers are allocated at enqueue, not at delivery, so a delivery that
fails and waits six hours keeps its position.

Head-of-line blocking is bounded, on purpose. Skipping a stuck event to
deliver the next one for the same transaction would deliver `success` while
`pending` is still queued — the exact corruption ordering exists to prevent.
Once the retry budget is spent the delivery dead-letters and the key unblocks
([ADR-003](docs/adr/0003-ordering-with-a-bounded-blocking-window.md)).

**What retries and what does not** turns on whether repeating the request
could plausibly work. A 5xx, a timeout, a 408 or a 429 could. A 400 saying the
payload is malformed will say the same thing in six hours, so retrying only
delays the dead letter an operator needs to see.

**A redirect is never followed.** Replaying a signed POST to a location the
tenant never registered is an SSRF primitive handed over willingly.

**The SSRF guard re-resolves at delivery time, inside the dialler.**
Validating only at registration is defeated by DNS rebinding: a hostname
resolves publicly long enough to pass the check, then repoints at
`169.254.169.254`, and the metadata service's response appears in the delivery
log. IPv4-mapped IPv6 is unmapped first, because `::ffff:169.254.169.254` is
the classic bypass.

**The circuit breaker parks rather than spending the budget.** Retries handle
one failing delivery; against a wholly-down destination they multiply load
against a service trying to recover. A parked delivery costs no attempt, so an
outage does not dead-letter everything queued during it at the moment the
customer's service returns.

### `internal/store` — tenant-scoped by construction

Every method that touches tenant-owned data takes `tenantID` as its first
argument, and no method exists that does not. A forgotten scope is a compile
error rather than a data breach.

**A row belonging to another tenant returns `ErrNotFound`, identical to a row
that does not exist.** A distinct "forbidden" would confirm the row is real,
which is a working cross-tenant enumeration oracle: an attacker with one valid
key could map another fintech's event IDs one request at a time.

Three queries carry most of the weight:

**`ClaimDue`** is where ordering is actually enforced. `DISTINCT ON
(destination_id, transaction_ref)` ordered by sequence takes only the earliest
pending delivery per transaction; a `NOT EXISTS` clause excludes references
another replica already holds; `FOR UPDATE SKIP LOCKED` lets replicas claim in
parallel without serialising on the same rows.

**`PutCanonicalEvent`** writes the event and marks its raw counterpart done in
one transaction. A canonical event without the raw marked is re-normalised and
rejected as a duplicate — survivable. A raw event marked done without a
canonical event is silently never forwarded — not.

**`AppendAudit`** takes a per-tenant advisory lock. Two concurrent appends both
reading the same head would produce two records claiming the same predecessor,
breaking the chain for reasons that have nothing to do with tampering.

`raw_events` is range-partitioned by month. It is the fastest-growing table
and the only one whose rows cannot be regenerated from anywhere, so retention
is a `DROP PARTITION` rather than a `DELETE` that leaves the table bloated.

### `internal/audit` — proving nothing was rewritten

Every state change is an immutable record, hash-chained per tenant.
Immutability is enforced, not promised:

- The application role has `INSERT` and `SELECT` on the audit table. No
  `UPDATE`, no `DELETE`.
- A `BEFORE UPDATE OR DELETE` trigger raises regardless of role — including
  for a superuser, whose mistakes nothing else catches. Asserted in the
  integration tests.
- Each hash covers its content plus its predecessor's, with **length prefixes**
  so content cannot be shifted across a field boundary undetected: actor `ab`
  with subject `c` must not collide with actor `a` and subject `bc`.
- A per-tenant gapless sequence, so a *deleted* record is named as a gap
  rather than merely detected as a broken hash.
- **Corrections are appended, never applied.** A wrong record is followed by
  one carrying `corrects: <id>`. An audit trail you can edit to fix a mistake
  is one you can edit to hide one.

Timestamps are truncated to microseconds before hashing. Go's clock gives
nanoseconds on Linux and Postgres stores microseconds, so a record sealed at
one precision and read back at another hashes differently — and every
verification then fails with "content does not match its stored hash", which
reads exactly like tampering. The bug is invisible on macOS, where the clock
happens to have microsecond granularity.

Nightly, each chain is walked and a **signed checkpoint** published. A hash
chain nobody verifies detects nothing. The ed25519 key lives outside the
database, so an attacker who alters a record must also forge every checkpoint
since — and the public key is published, so a customer's auditor checks it
without involving us. Failed verifications are published and signed too:
suppressing them is the most useful thing an attacker could arrange.

### `internal/auth` — API keys, and three layers of tenancy

Keys are `sh_{env}_{random}`, stored as an Argon2id hash with the parameters
encoded alongside so the cost can be raised without invalidating existing
keys. The environment is in the key itself, so a live key pasted into a test
configuration is catchable by inspection.

**The hash comparison runs before the revoked and expired checks.** Returning
early on a revoked key would make that check measurably faster, which tells an
attacker which of their stolen keys are still worth trying.

Tenancy is enforced at three independent layers, because one layer is a single
point of failure:

1. **Authentication** — a key resolves to exactly one tenant. No key spans
   tenants.
2. **Query** — every repository method takes `tenantID` first.
3. **Storage** — Postgres row-level security keyed on a session variable, so
   even a query that forgets to scope returns nothing.

`TestStoreTenantIsolation` and `TestPostgresTenantIsolation` are **blocking CI
gates**.

Roles are owner, engineer, support, read-only. The split that matters is
support and engineer: support can search events and replay deliveries — the
things they need hourly — but cannot change an adapter, which silently alters
what every future event from that provider means.

### `internal/ratelimit` — backpressure that says so

A per-tenant token bucket, not a fixed window. A fixed window lets a tenant
spend a whole minute's allowance in the first second and take the service down
for the other fifty-nine.

The ceiling matches the service's own load target — 10,000/sec sustained,
20,000 burst. An earlier default of 2,000/sec was **below** what the product
promises to carry, so a single large tenant sending exactly that was answered
with 429s. The load test found it.

A refusal always carries `Retry-After`, computed from the actual deficit
rather than a fixed guess, so a caller that honours it succeeds on its next
attempt instead of being refused again.

The concurrency ceiling refuses rather than blocks. Blocking would convert a
capacity problem into a latency problem, and the receiver's whole design is
that it answers fast or says no.

### `internal/silence` — the alert for nothing happening

Every alert in §11.4 fires on something happening. The failure none of them
catches is silence: a provider stops sending, or somebody overwrites the
receiver URL during an unrelated change, and every counter flattens. No error
is logged, because from our side nothing went wrong.

Detection is against each endpoint's own baseline, by **hour of week**.
Nigerian payment volume on a Sunday at 04:00 has nothing in common with a
Tuesday at 14:00, and a baseline averaging them would either alert every
weekend or never alert at all.

The floor is the *quietest* comparable hour, not the mean. A mean-based floor
alerts on any below-average hour, which is half of them.

Until an endpoint has three weeks of history for the hour in question, it
reports as **still learning** rather than healthy. Claiming to watch something
you cannot yet judge is worse than saying you are not watching it.

### `internal/region` — receivers everywhere, dispatchers in one place

A provider POSTing from Lagos to Frankfurt pays 90–150 ms before StatusHub
does any work, which is an argument for receivers close to providers. It is
not an argument for putting everything there.

Ordering is enforced by a database claim, and a claim only serialises against
claimants reading the same rows under the same locks. **A second dispatching
region delivers the same events twice, out of order, and nothing errors while
it happens** — the failure surfaces days later as "your ordering guarantee
does not work".

So the server refuses to start a dispatcher outside the primary region, and
the Helm chart does not render one at all in an edge region — not scaled to
zero, absent. A `replicas: 0` Deployment is one `kubectl scale` away from
being that second dispatcher, and the person running that command will be
under pressure and looking for capacity.

**Failover is a human decision**, deliberately. An automated promotion on a
network partition produces two primaries, and a false-positive failover is
worse than the outage it responds to. What is automated is making the decision
fast: `statushubctl doctor --replication` reports the assessment rather than
the number —

> `the WAL stream is not connected. The lag figure below is stale and the true
> gap is unknown — promoting now loses an unbounded amount.`

[ADR-006](docs/adr/0006-multi-region.md) and the
[failover runbook](docs/runbook-failover.md).

### `internal/subject` — export and erasure

§9 commits to *documented and tested* export and deletion. The failure mode of
an erasure is silence: a query matching nothing reports success just as loudly
as one that erased everything, so `Verify` is a separate step that can be run
against production on the day a regulator asks.

What is erased is everything tying a transaction to a person: the raw body —
where a name or phone number actually sits, because the provider chose the
payload — and `provider_extra`, where an unmapped `customer.phone` lives.

What is retained is the transaction, and the report says so plainly. CBN and
AML record-keeping require the tenant to hold transaction records for years,
and deleting a payment from their ledger at the payer's request would break
their books. Audit records are retained too: erasing the record that an
erasure happened is not a defensible reading of either regulation.

### `internal/usage` — a billing metric the customer can check

§2.4 chooses "events received" *because* the customer can reconcile it against
their provider dashboards. That only holds if the number is derived from the
same rows the event explorer shows — a separate counter drifts, and a bill
disagreeing with the customer's own view of the same data is worse than no
auditable metric.

So every figure is a query over `raw_events`. Slower than a counter, run
daily, and correct by construction: if the customer can see the event, it was
billed.

Forgeries are billed **and broken out**. The work of receiving, verifying and
storing them happened, and the customer's provider dashboard counts deliveries
attempted too — so a bill larger than theirs is explainable rather than
mysterious.

CSV export defuses spreadsheet formula injection on every field. A declarative
adapter's name is customer-supplied, and a CSV that executes on open is a real
finding in a real penetration test.

### `internal/alert` — pages, warnings, and not training people to ignore both

§11.4 defines eight conditions and assumes a Prometheus and an on-call
rotation. Most fintechs at this size have neither, and an alert nobody
receives is the same as no alert.

Severities are **fixed, not configurable**. A tenant who can downgrade "audit
chain broken" to a digest entry will, on the day it is noisy for an unrelated
reason — and then it is a warning nobody reads on the day it means what it
says.

Pages go immediately and individually; warnings batch into a digest grouped by
condition, so forty unknown statuses read as one problem. A condition already
firing does not re-notify for four hours, because re-notifying every
evaluation is how an alerting system teaches people to filter it into a
folder.

Every alert carries its **first action**, verbatim from §11.4. An alert
without one is a notification, and the difference is whether the person woken
up knows what to do.

### `internal/simulate` — proving an integration before a real transaction

`statushubctl simulate` posts correctly-signed sample payloads at a receiver
URL, using **the same corpus the adapter tests run against**. A simulator
built from separate fixtures drifts, and one that sends payloads the adapter
would reject is worse than none — it produces a green tick for an integration
that does not work. `TestSimulatorSignaturesVerifyAgainstEveryAdapter` drives
every sample through the real receiver.

Timestamps are freshened, in each provider's own format. Stripe's five-minute
window would otherwise reject every stored sample as a replay, and the
operator's first experience would be a 401 that looks like a configuration
problem.

### `internal/tunnel` — live events on a developer's laptop

`statushubctl listen` removes the largest cause of a stalled evaluation: an
engineer cannot develop against webhooks without a publicly reachable URL, so
they reach for a tunnel service, hand-craft payloads from documentation, or
test in staging with real money.

Long-polling, not a websocket: no inbound connection to the laptop, nothing to
keep alive through a hotel network. The payload is byte-identical to what the
real destination receives and signed the same way, because the point is
developing against the real thing.

**Events are copied, never diverted.** A developer running `listen` in the
wrong terminal must not silently break the customer's live integration.

Active sessions are visible to the whole team on the dashboard. A laptop
receiving live production payloads is something everybody should be able to
see.

### The dashboard

Vite and TypeScript, no runtime dependencies, built into the binary and served
at `/` by the same process that serves the API. Eight views: events, unknown
statuses, dead letters, endpoints, destinations, adapters, active listeners
and the audit chain.

**Same origin is the point.** A dashboard hosted elsewhere would need CORS
opened on an API that can replay payments and read every raw provider payload,
and would put the customer's key through a cross-origin request.

The key is held in `sessionStorage` and gone when the tab closes. A strict
content security policy means an injected script would have nowhere to send
it, and the page loads no external anything: a fintech's webhook console
should not tell a CDN when its operations team is looking at an incident, and
should not stop working when that CDN does.

Three things it deliberately refuses to flatter:

- **An empty audit chain is not a pass.** It verifies trivially, and a green
  tick would claim an audit trail is intact when there is no audit trail.
- **Status is never colour alone.** The word is always present, so a row
  survives being read by somebody who cannot distinguish the colours and
  survives being pasted into a chat window.
- **Times are always UTC.** An operator comparing this against a provider's
  dashboard and a customer's logs does not need one of the three telling a
  different story.

```bash
make web    # rebuild after changing anything under web/src
```

### `statushubctl doctor` — the preflight for what fails silently

Most of what goes wrong here does not announce itself. A schema the binary
does not expect surfaces later as a missing column. A secret reference that
does not resolve produces an endpoint rejecting every event as unverified,
which looks exactly like an attack.

**Clock skew is the one worth reading.** It breaks HMAC timestamp windows in
*both* directions and produces an error message that tells the operator
nothing. It is measured against an HTTP `Date` header rather than NTP,
because the question is agreement with the internet rather than with a
stratum-1 clock — and a container that cannot reach NTP can usually still make
an HTTPS request.

### `pkg/statushub` and `sdk/` — the client libraries

Three libraries, one job: make the piece of code the customer *does* have to
write impossible to get wrong. That piece is signature verification, and it is
the most commonly botched part of any webhook integration.

All three are **Apache-2.0**, so integrating needs no lawyer. The server is
BUSL-1.1; the libraries deliberately are not.

They stay in agreement through `sdk/fixtures/signature_vectors.json`,
generated by **the server's own signing code**. Three implementations agreeing
with each other but not with production is a real failure mode, and this is
the arrangement that makes it impossible.

---
## 4. Quick start

### See it work first

```bash
docker compose up
```

Postgres, the receiver on `:8080`, the dispatcher, and the management API and
dashboard on `:8081`.

```bash
export STATUSHUB_DATABASE_URL="postgres://statushub:statushub@localhost:5432/statushub?sslmode=disable"

statushubctl init --slug acme --name "Acme Payments" --env test
# tenant   acme (tnt_06G2R…)
# api key  sh_test_0gwq1vn2967yb3t18sq9a0m31wkn3ymszkbzhv0
#
# This key is shown once. It is stored as an Argon2id hash and cannot be recovered.
```

Export it — the calls below need it.

```bash
export KEY=sh_test_...

curl -s -X POST localhost:8081/v1/endpoints -H "Authorization: Bearer $KEY" \
  -d '{"provider":"paystack","environment":"test","secret_ref":"env://PAYSTACK_TEST"}'
# {"receiver_url":"http://localhost:8080/v1/hooks/acme/paystack/test/tok_3GMW…"}
```

That URL is the entire integration. Prove it works without waiting for a real
transaction:

```bash
statushubctl simulate --provider paystack --url "<receiver URL>" \
  --secret sk_test_demo --all

#   charge.success               200 in 1ms
#                                accepted and stored. It will be normalised and forwarded
#                                within a second or two.
#   charge.unmapped_status       200 in 2ms
#   …
```

Then look at what came out:

```bash
statushubctl events list --tenant acme
# 2026-08-11T09:14:31Z  paystack  TXN-2026-08-11-8842  success   5000000 NGN
# 2026-08-11T12:00:00Z  paystack  TXN-2026-08-11-9001  unknown    100000 NGN  unmapped:part_settled
```

Open <http://localhost:8081> and paste the key for the same view with the raw
payloads and every delivery attempt.

### Set it up properly

```bash
statushubctl secrets                    # generates the two secrets, with what each does
statushubctl migrate up                 # applies the schema and records what it applied
statushubctl partitions run             # provisions three months of partitions
statushubctl doctor --secret-ref env://PAYSTACK_LIVE
```

`migrate up` rather than piping the `.sql` files through `psql`: running them
by hand works but leaves no ledger, so every later `migrate up` reports the
schema as pending and then fails on a table that already exists.

`doctor` before pointing a provider at anything:

```
  ok      database               reachable in 5ms
  ok      migrations             up to date
  ok      clock skew             within 475ms of network time
  ok      secret env://…         resolves; 2 values valid, so a rotation overlap is in place
  ok      outbound https         reached https://api.paystack.co
```

### Developing against it

```bash
statushubctl listen --forward http://localhost:3000/hooks --key $KEY
```

Real events stream to your machine with the same payload and signature
production receives, so your verification code is exercised rather than
skipped. Your real destinations keep receiving everything — this is a copy.

### The handler you write

```go
http.Handle("/hooks/statushub", statushub.Handler(secret, func(w http.ResponseWriter, e statushub.Event) {
    switch e.Status {
    case statushub.StatusSuccess:
        ledger.Credit(e.TransactionRef, e.AmountMinor, e.Currency)
    case statushub.StatusFailed:
        ledger.Release(e.TransactionRef)
    case statushub.StatusUnknown:
        // StatusHub did not recognise the provider's value and refused to
        // guess. e.UnmappedStatus carries what they actually sent.
        review.Queue(e.TransactionRef, e.UnmappedStatus)
    }
    w.WriteHeader(http.StatusOK)
}))
```

That is the whole integration. It does not change when a provider is added.

---

## 5. API

Full [OpenAPI 3.1](docs/openapi.yaml), generated from the route table the
router itself is built from — CI fails when the two disagree.

```http
POST   /v1/endpoints                      create a receiver URL
POST   /v1/endpoints/{id}/rotate-token    rotate without changing the URL shape
GET    /v1/endpoints/{id}/signature-failures
POST   /v1/destinations
GET    /v1/adapters                       built-ins and your own, documented
POST   /v1/adapters                       upload a declarative adapter
POST   /v1/adapters/infer                 draft one from sample payloads
POST   /v1/adapters/{name}/test           dry run
GET    /v1/events?provider=&status=&transaction_ref=&mapping_complete=&from=&to=&cursor=
GET    /v1/events/{id}                    canonical event + every delivery attempt
GET    /v1/events/{id}/raw                the provider's original bytes (audited)
POST   /v1/events/{id}/replay
POST   /v1/events/replay                  by filter or time range
GET    /v1/deliveries?status=dead_letter
POST   /v1/deliveries/{id}/retry
GET    /v1/unknown-statuses               provider values awaiting mapping
GET    /v1/schema-versions
POST   /v1/listen                         stream live events to a local machine
GET    /v1/audit   GET /v1/audit/verify
POST   /v1/keys    GET /v1/keys    DELETE /v1/keys/{id}
GET    /healthz    GET /readyz     GET /metrics
```

**Errors.** A resource belonging to another tenant returns **404, never 403** —
a 403 confirms the resource exists. Authentication failures all return the
same bare 401: distinguishing "unknown key" from "revoked key" tells a caller
which of their stolen keys are real. A 403 means only that your key's role is
insufficient for a resource that is yours.

**Idempotency.** Every write accepts an `Idempotency-Key`. A retry with the
same key returns the original result and sets `Idempotency-Replayed: true`;
reusing a key with a different body is a 409.

### Verifying our signature

```js
import { verifySignature } from '@statushub/node';

// raw, not json — the signature covers the bytes that were sent, and a round
// trip through a parser changes them.
app.post('/hooks/statushub', express.raw({ type: 'application/json' }), (req, res) => {
  if (!verifySignature(req.body, req.headers['x-statushub-signature'], SECRET)) {
    return res.status(401).end();
  }
  handleEvent(JSON.parse(req.body));
  res.status(200).end();
});
```

The header is `t=<unix>,v1=<hex>`, an HMAC-SHA256 over `{timestamp}.{body}` —
deliberately Stripe's scheme. Well documented, widely implemented, and not a
novel cryptographic design invented by a webhook vendor.

Three things to get right if you implement it yourself: hash the **raw bytes**
before parsing, compare in **constant time**, and **check the timestamp** —
the digest on a captured delivery stays valid forever, and only the window
stops a replay. During a rotation the header carries several `v1=` values and
any one matching is enough.

---

## 6. Correctness notes

### Out-of-order events

Events sharing a `transaction_ref` are delivered sequentially, and the
sequence is allocated at enqueue rather than at delivery. A delivery that
fails and waits six hours keeps its position, so an event queued after it
cannot overtake it while it waits.

### A provider redelivering

Deduplication is `(tenant, provider, provider_event_id)`, enforced by a unique
index rather than a check-then-insert — two receiver replicas processing a
retry at the same moment would both pass an application check and both write.

Providers that supply no event ID, like Paystack, fall back to the body hash.
That is correct for them specifically because they redeliver byte-identical
payloads, and the adapter says so rather than assuming it.

Four identical redeliveries produce four raw events — each arrival is a fact
worth recording — and one canonical event.

### A crash between persisting and acknowledging

The provider sees a failure and retries. The retry deduplicates, so the
customer's ledger sees one payment. `TestChaosReceiverKilledBetweenPersistAndAcknowledge`
asserts exactly that.

### A dispatcher killed mid-delivery

Deliveries are leased. A replica that dies holds its lease until it expires,
after which another reclaims the work — so a crash costs one lease interval of
latency on one key rather than a permanently stalled shard.

The customer may see one event twice, and every attempt carries the same
`Idempotency-Key`, which is what turns our at-least-once into their
exactly-once. The chaos suite measures it: killing a dispatcher mid-delivery
produced **one duplicate out of twenty**.

### Ordering across replicas

`ClaimDue` returns at most one in-flight delivery per `(destination,
transaction_ref)`, and excludes references another replica already holds under
an unexpired lease. `FOR UPDATE SKIP LOCKED` lets replicas claim in parallel
without serialising.

Across *regions* this does not hold, which is why dispatchers run in exactly
one ([ADR-006](docs/adr/0006-multi-region.md)).

### A destination that is down entirely

Retries handle one failing delivery; against a wholly-down destination they
multiply load against a service trying to recover. The breaker parks
deliveries **without consuming an attempt**, so a nine-hour outage does not
dead-letter everything queued during it at the moment the customer's service
returns. Bounded at 24 hours: past that the destination is not having an
outage, it is gone.

---

## 7. Configuration

Every flag has a `STATUSHUB_`-prefixed environment variable.

| Variable | Default | |
|---|---|---|
| `STATUSHUB_MODE` | `all` | `receiver`, `dispatcher`, `api`, or `all` |
| `STATUSHUB_DATABASE_URL` | — | required for the Postgres store |
| `STATUSHUB_STORE` | `postgres` | `memory` is refused in the live environment |
| `STATUSHUB_ENVIRONMENT` | `test` | `live` turns on the strict validations |
| `STATUSHUB_BASE_URL` | `http://localhost:8080` | must be https when live |
| `STATUSHUB_TENANT_SALT_MASTER` | — | **required when live**; every tenant's salt derives from it |
| `STATUSHUB_REGION` | `default` | labels every metric and log line |
| `STATUSHUB_REGION_ROLE` | `primary` | `edge` refuses to run a dispatcher |
| `STATUSHUB_DB_WRITE_BUDGET` | 25ms / 120ms | by role; exceeding it raises the latency alert |
| `STATUSHUB_SHARDS` | `64` | changing this is a migration, not a tweak |
| `STATUSHUB_RECEIVE_PER_SECOND` | `10000` | per tenant |
| `STATUSHUB_RECEIVE_BURST` | `20000` | |
| `STATUSHUB_TRUST_PROXY_HEADERS` | `false` | only behind a proxy you control |
| `STATUSHUB_BLOCKED_CIDRS` | — | ranges destinations may never resolve to |
| `STATUSHUB_SHUTDOWN_GRACE` | `30s` | set `terminationGracePeriodSeconds` above this |

Secrets are never stored. The database holds a reference such as
`env://PAYSTACK_LIVE`, and the usable value is resolved at the moment it is
needed — so a database dump is not a credential breach.

`statushubctl secrets` generates the two the deployment needs and explains
what losing or replacing each one does.

---

## 8. Data handling

| Class | Rule |
|---|---|
| PAN, CVV, full card data | **Never stored.** Any 13–19 digit string passing Luhn is replaced before storage; the redaction is counted, logged and visible on the event. |
| Customer name, email, phone | Hashed with a **per-tenant** salt. HMAC, not a plain digest — a plain SHA-256 of an email is reversible with a wordlist in seconds — and per-tenant, so one tenant's leaked data cannot correlate a person across another's. |
| Raw payloads, references, amounts | Retained with configurable retention; access separately permissioned and independently audited. |

*"We cannot leak what we never collected"* is a far stronger position than
*"we encrypt it well."*

**Retention.** Raw events 30 days by default, canonical events 90 days, audit
records 7 years — enforced by dropping monthly partitions rather than deleting
rows. The partition job provisions three months ahead and recovers rows
stranded in the catch-all, so a missed run is not permanent.

**Subject rights.** `Export` gathers everything held; `Erase` removes every
link to the person and `Verify` proves it. The transactions themselves are
retained, and the report says so: CBN and AML obligations require the tenant
to hold them, and deleting a payment from their ledger at the payer's request
would break their books.

---

## 9. Development

```bash
make help              # every target, described
make test              # unit tests with the race detector, no database needed
make test-integration  # the full suite, against a real Postgres
make test-isolation    # the tenant isolation gate on its own
make test-adapters     # every adapter against its captured payloads
make test-chaos        # kill components mid-flight; assert nothing is lost
make loadtest          # k6 against a running receiver
make web               # rebuild the dashboard
make openapi           # regenerate docs/openapi.yaml from the routes
make ci                # what CI runs
```

`go test ./tests/...` works on a laptop with nothing installed — the Postgres
tests skip rather than fail. CI always sets `STATUSHUB_TEST_DATABASE_URL`, so
the integration path is never skipped where it matters.

Tests live in `tests/` rather than beside each package, so they exercise only
the exported API — the same surface a caller gets.

| Layer | Approach |
|---|---|
| Adapter | Every adapter against a corpus of real captured payloads. Every status value in every mapping table has a case. |
| Security | Signature verification against known-good and known-bad vectors per provider. Constant-time comparison asserted, not assumed. |
| Isolation | Two tenants, every read path, 404 rather than 403. Blocking gate. |
| Ordering | Concurrent events sharing a `transaction_ref` must reach the sink in order. |
| Failure | Sink returns 500 → assert the schedule. Sink flaps → assert eventual delivery. Dispatcher dies → assert the lease is reclaimed. |
| Chaos | A dispatcher killed mid-delivery, a receiver killed between persist and acknowledge, the dispatcher absent entirely. |
| Load | k6 at the §11.9 profile, with the 50 ms p99 as a threshold so the run fails when the SLO is missed. |

**An observed load run**, on a laptop also hosting Postgres and k6:

```
1,500/sec steady, bursting to 4,500/sec
172,418 accepted · 0 rejected · 0 throttled
p95 8.9ms   p99 27.9ms   (budget 50ms)
```

---

## 10. Layout

```
cmd/statushub/          server binary — receiver, dispatcher, api, or all
cmd/statushubctl/       admin CLI: init, doctor, listen, simulate, infer,
                        partitions, usage, secrets, openapi, migrate, …
internal/domain/        canonical schema, status enum, amounts, audit records
internal/adapter/       what a provider integration must do; HMAC + time primitives
internal/adapters/      the six built-ins, the declarative adapter, the registry
internal/jsonpath/      the deliberately small, bounded expression subset
internal/receive/       HTTP receiver — verify, persist, acknowledge
internal/normalise/     raw bytes → canonical events, off the request path
internal/dispatch/      ordered delivery, retries, DLQ, replay, breaker, SSRF guard
internal/store/         Postgres and in-memory implementations of one interface
internal/api/           the management API and its route table
internal/auth/          API keys, roles, the authenticated identity
internal/audit/         signed checkpoints and chain verification
internal/region/        multi-region placement and replica assessment
internal/redact/        card data removed before storage
internal/secret/        secret references resolved at use, never stored
internal/silence/       the alert for nothing happening
internal/alert/         routing to somewhere a person will see it
internal/usage/         the billing metric, counted from what the explorer shows
internal/subject/       data subject export and erasure
internal/simulate/      correctly-signed sample payloads per provider
internal/tunnel/        live events streamed to a developer's machine
internal/ratelimit/     per-tenant backpressure and bounded semaphores
internal/retention/     partition provisioning and expiry
internal/metrics/       the Prometheus surface
internal/migrate/       embedded, versioned schema changes
internal/server/        wiring and lifecycle
pkg/statushub/          the Go client library (Apache-2.0)
sdk/{node,python}/      the other two, verified against server-generated vectors
web/                    Vite + TypeScript dashboard, embedded into the binary
deploy/{helm,terraform}/
loadtest/               k6, with the SLO as a threshold
migrations/             reviewed separately from code, embedded into the binary
docs/adr/               the decisions worth defending
docs/openapi.yaml       generated from the routes
tests/                  the whole suite, against the exported API only
```

---

## 11. Licensing

Business Source License 1.1, converting to Apache-2.0 on 2030-08-23. You may
run StatusHub in production to receive, normalise and forward your own
webhooks or your customers'. You may not offer it to third parties as a hosted
webhook service.

The client libraries in `sdk/` and `pkg/statushub` are **Apache-2.0**, so
integrating needs no lawyer.

---

## 12. Status

Everything in the specification is built and tested: the receiver, six
adapters, the normalisation engine, the sharded dispatcher, declarative
adapters, the management API, the audit chain, the Postgres store, the CLI,
the dashboard and three client libraries.

Beyond it: `listen`, `simulate`, shadow mode, adapter inference, a circuit
breaker, explicit backpressure, silence detection, partition management,
idempotency keys, signed audit checkpoints, subject rights, usage metering,
alert routing, schema versioning, multi-region, a generated OpenAPI document,
Helm and Terraform, a signed release pipeline, and chaos and load suites.

**Not built, deliberately:** Kafka/SQS sink delivery. §3.3 puts it out of
scope for v1, and forwarding to a bus rather than an endpoint changes what
ordering and replay even mean — it is a product decision rather than an
unfinished one.

### Decisions worth reading

- **[ADR-001](docs/adr/0001-persist-then-acknowledge.md)** — Persist, then
  acknowledge, then process. Why every other ordering either loses events or
  creates duplicates.
- **[ADR-002](docs/adr/0002-redact-card-data-rather-than-reject.md)** — Redact
  card data rather than reject the payload. Why refusing a payment
  notification to avoid storing a card number the provider should not have
  sent trades a recoverable problem for an unrecoverable one.
- **[ADR-003](docs/adr/0003-ordering-with-a-bounded-blocking-window.md)** —
  Per-transaction ordering with a bounded blocking window. Where ordering and
  throughput are traded off, and why the bound is the retry budget.
- **[ADR-004](docs/adr/0004-derive-tenant-salts-from-one-master.md)** — Derive
  per-tenant salts rather than provisioning them. A control whose absence is
  invisible is not a control.
- **[ADR-005](docs/adr/0005-park-during-outages-rather-than-dead-letter.md)** —
  A destination-wide outage parks deliveries. Why a retry budget designed for
  one failing event is the wrong instrument for a destination that is down.
- **[ADR-006](docs/adr/0006-multi-region.md)** — Receivers in every region,
  dispatchers in exactly one. Why ordering cannot survive two regions
  claiming, and why failover is a human decision.
