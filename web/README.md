# The dashboard

Vite and TypeScript, no runtime dependencies, built into the binary and served
at `/` by the same process that serves the API.

```bash
make web        # rebuild and stage into web/embed/dist after any change here
npm run dev     # live reload, proxying /v1 to a local StatusHub on :8081
```

`web/embed/dist` is **committed**. Building the dashboard as part of the Go
build would put a Node toolchain in the path of anybody compiling the server —
a customer's pipeline, a security team reproducing a release. `go build` needs
Go and nothing else, and the cost is remembering `make web`. CI enforces that.

## Same origin is the point

A dashboard hosted elsewhere would need CORS opened on an API that can replay
payments and read every raw provider payload, and would put the customer's key
through a cross-origin request. Serving it from the binary needs neither, and
there is nothing extra to deploy.

The key lives in `sessionStorage` and is gone when the tab closes — a key that
outlives the session on a shared machine is a credential left lying around,
and this one reads every event a tenant has and can replay any of them. A
strict content security policy means an injected script would have nowhere to
send it, and the page loads no external anything: a fintech's webhook console
should not tell a CDN when its operations team is looking at an incident, and
should not stop working when that CDN does.

## Eight views

| | |
|---|---|
| **Events** | The screen somebody opens at 2am. Search by transaction reference, filter on mapping-incomplete. Click through to every delivery attempt. |
| **Unknown statuses** | Provider values with no mapping, ranked by frequency — the adapter work worth doing next. |
| **Dead letters** | With the response body, because "returned 400" is not a diagnosis and "returned 400 saying unknown currency" is. |
| **Endpoints** | The receiver URLs, and each adapter's stated weaker guarantee where it has one. |
| **Destinations** | Including the pinned schema version, so nobody has to guess which shape a handler receives. |
| **Adapters** | Each documenting its own signature scheme, including where that scheme is weaker than the others. |
| **Listening** | Who is streaming live events to a laptop. Visible to the whole team on purpose. |
| **Audit** | The hash chain, and every state change. |

## Three things it deliberately refuses to flatter

- **An empty audit chain is not a pass.** It verifies trivially, and a green
  tick would claim an audit trail is intact when there is no audit trail.
- **Status is never colour alone.** The word is always present, so a row
  survives being read by somebody who cannot distinguish the colours and
  survives being pasted into a chat window as text.
- **Times are always UTC, never localised.** An operator comparing this
  against a provider's dashboard and a customer's logs does not need one of
  the three telling a different story.

## Money is shifted, never divided

`amount_minor` is integer minor units, and the exponent is per currency — kobo
and cents have two, yen has none, the Gulf dinars have three. A
divide-by-100 would misstate JPY by exactly a hundredfold. `format.ts` shifts
the digits instead, which is the same arithmetic the server does and cannot
round.
