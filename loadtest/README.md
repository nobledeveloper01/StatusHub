# Load testing

```bash
make loadtest
```

Targets the profile from §11.9: **10,000 webhooks/sec across six providers,
receiver p99 under 50 ms.**

## Why the shape is what it is

**Arrival rate, not virtual users.** A VU-based test measures how fast the
system can be driven. A rate-based one measures whether it keeps up with a
rate somebody promised — which is what an SLO is.

**Six providers, each with its real signing scheme.** The adapters differ in
the expensive place: NIBSS and Interswitch have to parse the payload before
they can verify it, which is measurably more work than an HMAC over raw bytes.
A run against Paystack alone flatters the numbers.

**A burst on top of the steady rate.** Providers deliver in bursts after their
own outages. A receiver that only meets its SLO under smooth load has not met
it.

**The SLO is a threshold, so the run fails when it is missed.** A load script
that reports numbers and passes regardless is one nobody looks at after the
first week.

## Reading the result

| | |
|---|---|
| **p99 over 50 ms** | Providers will start retrying. Check store write latency first — the receiver's budget is spent almost entirely on one INSERT. |
| **Any 5xx** | A potentially lost event: a provider that gets a 500 may never retry. The threshold is `rate<0.0001` for that reason, not as a round number. |
| **429s** | Backpressure working. A handful is healthy; hundreds means the per-tenant ceiling is set below what this tenant legitimately sends. |

## An observed run

On a laptop also running Postgres and k6 themselves — so well below the
hardware §11.9 assumes — the receiver held:

```
  1,500/sec steady, bursting to 4,500/sec
  172,418 accepted, 0 rejected, 0 throttled
  p95 8.9ms   p99 27.9ms   (budget: 50ms)
```

Every threshold passed. That is not the §11.9 number and is not claimed to be:
it is one machine sharing its CPU with the database it is writing to. What it
does establish is that the budget is not spent somewhere unexpected — the
receiver's time goes almost entirely into the one INSERT, as the design
assumes, rather than into signature verification or JSON handling.

Two things this run found, which is what a load test is for:

- **The per-tenant rate limit defaulted to 2,000/sec**, below the 10,000/sec
  the product's own load target promises. A single large tenant sending what
  the service is specced to carry would have been answered with 429s. Now
  10,000/sec sustained with a 20,000 burst, and configurable.
- **p99 was absent from the summary**, because k6 does not report it by
  default — so the SLO the thresholds enforce was missing from the report a
  human reads. A number nobody sees is a number nobody acts on.

## Setting it up

```bash
statushubctl init --slug loadtest --env test
statushubctl endpoints create --tenant loadtest --provider paystack --env test --secret-ref env://LOAD_SECRET
# …repeat for the other five

k6 run loadtest/receive.js \
  -e BASE_URL=http://localhost:8080 \
  -e TENANT=loadtest \
  -e ENDPOINTS='paystack=tok_…:secret,stripe=tok_…:secret,…'
```

Point it at a receiver running against a real Postgres. Against the in-memory
store the numbers are meaningless — the whole budget is the one INSERT this
test exists to measure.
