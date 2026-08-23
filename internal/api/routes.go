package api

import (
	"net/http"

	"github.com/nobledeveloper01/StatusHub/internal/api/openapi"
	"github.com/nobledeveloper01/StatusHub/internal/auth"
)

// routeSpec is one route's declaration: what it is, who may call it, and
// enough prose for the generated OpenAPI document to be worth reading.
//
// The router and the specification are built from this same slice. That is
// the whole point — a specification maintained beside the code drifts, and a
// generated client that calls an endpoint which no longer exists is worse
// than no client at all.
type routeSpec struct {
	Method string
	Path   string
	Role   auth.Role

	// Public marks a route with no authentication.
	Public bool

	// Idempotent marks a write wrapped by the idempotency middleware.
	Idempotent bool

	Summary     string
	Description string

	Params          []openapi.Param
	RequestExample  string
	ResponseExample string

	// handler is resolved at mux-build time. Held as a selector rather than
	// a value so the table can be a package-level declaration.
	handler func(*Server) http.HandlerFunc
}

// routes is the single source of truth for the management API.
var routes = []routeSpec{
	// --- health and metrics -------------------------------------------------
	{
		Method: "GET", Path: "/healthz", Public: true,
		Summary:     "Liveness",
		Description: "Whether the process is alive. Separate from readiness: a readiness failure should remove an instance from rotation, and a health failure should restart it. Conflating them turns a slow database into a restart loop.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleHealthz },
	},
	{
		Method: "GET", Path: "/readyz", Public: true,
		Summary: "Readiness",
		Description: "Whether this instance can do its job. For the receiver that means one thing — can it write a raw event — and deliberately says nothing about the dispatcher. " +
			"A shared probe would take the receiver out of rotation for a dispatcher fault, losing precisely the events persist-then-acknowledge exists to protect.",
		handler: func(s *Server) http.HandlerFunc { return s.handleReadyz },
	},
	{
		Method: "GET", Path: "/metrics", Public: true,
		Summary:     "Prometheus metrics",
		Description: "The series from §11.2. `statushub_status_unknown_total{raw_value}` is quietly the most useful of them: a live feed of exactly which provider status values have no mapping yet.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleMetrics },
	},

	// --- endpoints ----------------------------------------------------------
	{
		Method: "POST", Path: "/v1/endpoints", Role: auth.RoleEngineer, Idempotent: true,
		Summary: "Create a receiver URL",
		Description: "Returns the URL to paste into the provider's dashboard. That paste is the entire integration — nothing in your codebase changes, except deleting the parsing code you no longer need.\n\n" +
			"`secret_ref` is a reference into your secret manager, never a secret. The database holds the reference, so a database dump is not a credential breach.",
		RequestExample:  "provider: paystack\nenvironment: live\nsecret_ref: \"env://PAYSTACK_LIVE\"",
		ResponseExample: "id: ep_06G2R…\nprovider: paystack\nenvironment: live\nadapter: paystack\nreceiver_url: \"https://hooks.statushub.dev/v1/hooks/acme/paystack/live/tok_9f2a…\"\nsecret_ref: \"env://PAYSTACK_LIVE\"\nenabled: true",
		handler:         func(s *Server) http.HandlerFunc { return s.handleCreateEndpoint },
	},
	{
		Method: "GET", Path: "/v1/endpoints", Role: auth.RoleReadOnly,
		Summary: "List receiver URLs",
		handler: func(s *Server) http.HandlerFunc { return s.handleListEndpoints },
	},
	{
		Method: "GET", Path: "/v1/endpoints/{id}", Role: auth.RoleReadOnly,
		Summary: "Get a receiver URL",
		handler: func(s *Server) http.HandlerFunc { return s.handleGetEndpoint },
	},
	{
		Method: "DELETE", Path: "/v1/endpoints/{id}", Role: auth.RoleEngineer,
		Summary:     "Delete a receiver URL",
		Description: "The events it received are retained. Deleting an endpoint removes the URL, not the history — those events are the evidence of what the provider reported and when.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleDeleteEndpoint },
	},
	{
		Method: "POST", Path: "/v1/endpoints/{id}/rotate-token", Role: auth.RoleEngineer, Idempotent: true,
		Summary: "Rotate a receiver token",
		Description: "Only the token changes; the URL keeps its shape, so rotating is a one-line edit in the provider's dashboard rather than a reconfiguration.\n\n" +
			"The previous token stops working immediately. That is the point — a token is rotated because it leaked.",
		handler: func(s *Server) http.HandlerFunc { return s.handleRotateToken },
	},
	{
		Method: "GET", Path: "/v1/endpoints/{id}/signature-failures", Role: auth.RoleSupport,
		Summary: "Requests that failed verification",
		Description: "Events with an invalid signature are stored, flagged, and never forwarded. Discarding them would destroy the forensic trail of an attack in progress; forwarding them is the vulnerability itself.\n\n" +
			"A spike here from one source is a paging alert: a burst of forgery attempts is information you need within minutes.",
		Params:  []openapi.Param{{Name: "since", In: "query", Description: "RFC 3339. Defaults to 24 hours ago."}},
		handler: func(s *Server) http.HandlerFunc { return s.handleSignatureFailures },
	},

	// --- destinations -------------------------------------------------------
	{
		Method: "POST", Path: "/v1/destinations", Role: auth.RoleEngineer, Idempotent: true,
		Summary: "Create a forwarding target",
		Description: "Must be HTTPS and must resolve to a publicly routable address. Both are checked here and again inside the dialler at delivery time — validating only at registration is defeated by DNS rebinding.\n\n" +
			"A destination keeps the schema version it was created with. A newer version never moves an existing handler on its own.",
		RequestExample: "name: ledger\nurl: \"https://acme.io/hooks/statushub\"\nsigning_secret_ref: \"env://ACME_SIGNING\"\nfilter:\n  statuses: [success, reversed]",
		handler:        func(s *Server) http.HandlerFunc { return s.handleCreateDestination },
	},
	{
		Method: "GET", Path: "/v1/destinations", Role: auth.RoleReadOnly,
		Summary: "List forwarding targets",
		handler: func(s *Server) http.HandlerFunc { return s.handleListDestinations },
	},
	{
		Method: "GET", Path: "/v1/destinations/{id}", Role: auth.RoleReadOnly,
		Summary: "Get a forwarding target",
		handler: func(s *Server) http.HandlerFunc { return s.handleGetDestination },
	},
	{
		Method: "DELETE", Path: "/v1/destinations/{id}", Role: auth.RoleEngineer,
		Summary: "Delete a forwarding target",
		handler: func(s *Server) http.HandlerFunc { return s.handleDeleteDestination },
	},

	// --- schema versions ----------------------------------------------------
	{
		Method: "GET", Path: "/v1/schema-versions", Role: auth.RoleReadOnly,
		Summary:     "Payload schema versions",
		Description: "What shapes are served and when one retires. Published so a version change is something you read about rather than discover from a broken handler.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleSchemaVersions },
	},

	// --- adapters -----------------------------------------------------------
	{
		Method: "GET", Path: "/v1/adapters", Role: auth.RoleReadOnly,
		Summary:     "List adapters",
		Description: "Built-in adapters and your own. Each documents its signature scheme, its status mapping, and — where it applies — the ways in which it is weaker than the others. Worth reading before relying on one.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleListAdapters },
	},
	{
		Method: "POST", Path: "/v1/adapters", Role: auth.RoleEngineer, Idempotent: true,
		Summary: "Upload a declarative adapter",
		Description: "Adapters are configuration, not code — which is what lets you support a provider StatusHub has never heard of without opening a ticket.\n\n" +
			"Supply `samples`: they are run before the adapter is stored, and one that does not parse blocks the upload. You supplied it as an example of what the provider sends, so an adapter that cannot read it is not ready.",
		handler: func(s *Server) http.HandlerFunc { return s.handleUploadAdapter },
	},
	{
		Method: "POST", Path: "/v1/adapters/infer", Role: auth.RoleEngineer,
		Summary:     "Draft an adapter from sample payloads",
		Description: "Proposes a configuration with each guess's reasoning and confidence attached. Stores nothing and activates nothing: the amount unit and the timezone are guesses that cost real money when wrong, and both are flagged for review.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleInferAdapter },
	},
	{
		Method: "POST", Path: "/v1/adapters/{name}/test", Role: auth.RoleEngineer,
		Summary:     "Dry-run an adapter against sample payloads",
		Description: "Stores nothing and activates nothing. The useful output is the warnings, not the green tick: an adapter that parses every sample and still has no event ID mapped will duplicate events on the provider's first retry, and nobody discovers that from a pass.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleTestAdapter },
	},
	{
		Method: "DELETE", Path: "/v1/adapters/{name}", Role: auth.RoleEngineer,
		Summary:     "Delete a declarative adapter",
		Description: "Refused while an endpoint still uses it. That endpoint would keep receiving webhooks it could no longer verify, storing every one flagged invalid and forwarding none — which looks exactly like an attack.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleDeleteAdapter },
	},

	// --- events -------------------------------------------------------------
	{
		Method: "GET", Path: "/v1/events", Role: auth.RoleReadOnly,
		Summary: "Search events",
		Description: "The event explorer. Search by transaction reference when a customer asks about one payment; filter on `mapping_complete=false` to see what StatusHub itself was unsure about.\n\n" +
			"Keyset pagination via `cursor`, never OFFSET — this is the largest table anybody queries interactively.",
		Params: []openapi.Param{
			{Name: "provider", In: "query"},
			{Name: "status", In: "query", Description: "pending, success, failed, reversed, abandoned or unknown."},
			{Name: "event_type", In: "query"},
			{Name: "transaction_ref", In: "query"},
			{Name: "mapping_complete", In: "query", Schema: "boolean", Description: "Set false to find events StatusHub could not fully map."},
			{Name: "from", In: "query", Description: "RFC 3339."},
			{Name: "to", In: "query", Description: "RFC 3339."},
			{Name: "cursor", In: "query", Description: "The `next_cursor` from the previous page."},
			{Name: "limit", In: "query", Schema: "integer"},
		},
		handler: func(s *Server) http.HandlerFunc { return s.handleQueryEvents },
	},
	{
		Method: "GET", Path: "/v1/events/{id}", Role: auth.RoleReadOnly,
		Summary:     "Get an event and every delivery attempt",
		Description: "Each attempt with its response code, response body and duration. \"Their endpoint returned 400\" is not a diagnosis; \"returned 400 saying unknown currency\" is.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleGetEvent },
	},
	{
		Method: "GET", Path: "/v1/events/{id}/raw", Role: auth.RoleSupport,
		Summary:     "Get the provider's original payload",
		Description: "Separately permissioned and separately audited. Raw bodies are the most sensitive thing StatusHub holds — they are whatever the provider chose to send — so reading one is an event in its own right.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleGetRawPayload },
	},
	{
		Method: "POST", Path: "/v1/events/{id}/replay", Role: auth.RoleSupport, Idempotent: true,
		Summary: "Replay one event",
		Description: "Sends the stored canonical event again, carrying `X-StatusHub-Replay: true` and the same `Idempotency-Key`, so a handler that already processed it recognises it.\n\n" +
			"Nothing is re-normalised: a replay reproduces exactly what you would have received the first time, rather than silently differing because someone edited an adapter last week.",
		handler: func(s *Server) http.HandlerFunc { return s.handleReplayEvent },
	},
	{
		Method: "POST", Path: "/v1/events/replay", Role: auth.RoleSupport, Idempotent: true,
		Summary: "Replay by filter or time range",
		Description: "The recovery tool. **Send `dry_run: true` first** — a bulk replay is the easiest way to send your own systems a million requests at four in the morning, and the dry run tells you how big the window is before you commit to it.\n\n" +
			"Destination filters still apply, so a replay does not send an analytics sink the pending events it deliberately excluded.",
		RequestExample: "provider: paystack\nfrom: \"2026-08-11T00:00:00Z\"\nto: \"2026-08-11T12:00:00Z\"\ndry_run: true",
		handler:        func(s *Server) http.HandlerFunc { return s.handleBulkReplay },
	},

	// --- deliveries ---------------------------------------------------------
	{
		Method: "GET", Path: "/v1/deliveries", Role: auth.RoleReadOnly,
		Summary: "Search deliveries",
		Params: []openapi.Param{
			{Name: "status", In: "query", Description: "pending, in_flight, succeeded, failed or dead_letter."},
			{Name: "destination_id", In: "query"},
			{Name: "event_id", In: "query"},
			{Name: "cursor", In: "query", Schema: "integer"},
			{Name: "limit", In: "query", Schema: "integer"},
		},
		handler: func(s *Server) http.HandlerFunc { return s.handleQueryDeliveries },
	},
	{
		Method: "POST", Path: "/v1/deliveries/{id}/retry", Role: auth.RoleSupport, Idempotent: true,
		Summary:     "Retry a dead letter",
		Description: "Creates a *new* delivery. The dead letter is preserved: it records what the destination said and when, and overwriting it to try again would destroy the evidence of the failure that prompted the retry.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleRetryDelivery },
	},

	// --- unknown statuses ---------------------------------------------------
	{
		Method: "GET", Path: "/v1/unknown-statuses", Role: auth.RoleReadOnly,
		Summary: "Provider values awaiting a mapping",
		Description: "Ranked by frequency. Each is a provider status StatusHub does not recognise; events carrying them were forwarded as `unknown` rather than guessed at.\n\n" +
			"This is the product telling you what to build next instead of waiting for a customer to report it.",
		Params:  []openapi.Param{{Name: "since", In: "query", Description: "RFC 3339. Defaults to 30 days ago."}},
		handler: func(s *Server) http.HandlerFunc { return s.handleUnknownStatuses },
	},

	// --- listen -------------------------------------------------------------
	{
		Method: "POST", Path: "/v1/listen", Role: auth.RoleEngineer,
		Summary: "Start streaming events to a local machine",
		Description: "Backs `statushubctl listen`. Events are **copied**, never diverted: your real destinations keep receiving everything.\n\n" +
			"Engineer role rather than read-only, because streaming live production payloads to an arbitrary machine is a data-egress decision rather than a read.",
		handler: func(s *Server) http.HandlerFunc { return s.handleStartListen },
	},
	{
		Method: "GET", Path: "/v1/listen", Role: auth.RoleReadOnly,
		Summary:     "List active listen sessions",
		Description: "Visible to the whole team, deliberately: a laptop receiving live production events is something everybody should be able to see.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleListListen },
	},
	{
		Method: "GET", Path: "/v1/listen/{id}/poll", Role: auth.RoleEngineer,
		Summary:     "Long-poll for queued events",
		Description: "Blocks up to 25 seconds — under the idle timeout most proxies impose without telling anybody — then returns empty. An empty return is the normal case on a quiet endpoint, not an error.",
		Params:      []openapi.Param{{Name: "max", In: "query", Schema: "integer"}},
		handler:     func(s *Server) http.HandlerFunc { return s.handlePollListen },
	},
	{
		Method: "POST", Path: "/v1/listen/{id}/report", Role: auth.RoleEngineer,
		Summary:     "Report what the local handler said",
		Description: "So the CLI's tally and the dashboard's are the same one.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleReportListen },
	},
	{
		Method: "DELETE", Path: "/v1/listen/{id}", Role: auth.RoleEngineer,
		Summary: "Stop a listen session",
		handler: func(s *Server) http.HandlerFunc { return s.handleStopListen },
	},

	// --- audit --------------------------------------------------------------
	{
		Method: "GET", Path: "/v1/audit", Role: auth.RoleReadOnly,
		Summary: "The audit trail",
		Params: []openapi.Param{
			{Name: "since", In: "query", Description: "RFC 3339. Defaults to 7 days ago."},
			{Name: "limit", In: "query", Schema: "integer"},
		},
		handler: func(s *Server) http.HandlerFunc { return s.handleListAudit },
	},
	{
		Method: "GET", Path: "/v1/audit/verify", Role: auth.RoleReadOnly,
		Summary: "Verify the hash chain",
		Description: "Walks your tenant's chain and reports the first break. Returns **409** on a broken chain, so anything polling this sees a failure without parsing the body.\n\n" +
			"Exposed to you rather than kept internal on purpose: an audit trail whose integrity only the vendor can check is one you have to take on trust, which is what an audit trail exists to avoid.",
		handler: func(s *Server) http.HandlerFunc { return s.handleVerifyAudit },
	},

	// --- keys ---------------------------------------------------------------
	{
		Method: "POST", Path: "/v1/keys", Role: auth.RoleOwner, Idempotent: true,
		Summary: "Create an API key",
		Description: "The plaintext appears in this response and nowhere else, ever. It is stored as an Argon2id hash and cannot be recovered.\n\n" +
			"Owner only: a key that can issue keys can escalate to any role. A key also cannot issue keys for an environment other than its own.",
		RequestExample: "name: ci\nrole: engineer\nenvironment: live",
		handler:        func(s *Server) http.HandlerFunc { return s.handleCreateKey },
	},
	{
		Method: "GET", Path: "/v1/keys", Role: auth.RoleOwner,
		Summary:     "List API keys",
		Description: "With last-used times, because the most useful thing to do with this list is revoke the keys nobody has used in six months.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleListKeys },
	},
	{
		Method: "DELETE", Path: "/v1/keys/{id}", Role: auth.RoleOwner,
		Summary:     "Revoke an API key",
		Description: "Refused for the key you are authenticated with. Locking yourself out of your own account with no way back in is worse than being technically correct about what revoke means.",
		handler:     func(s *Server) http.HandlerFunc { return s.handleRevokeKey },
	},
}

// OpenAPIDocument renders the specification from the same table the router is
// built from.
func OpenAPIDocument(version string) string {
	doc := openapi.Document{Version: version}
	for _, r := range routes {
		role := ""
		if !r.Public {
			role = r.Role.String()
		}
		doc.Routes = append(doc.Routes, openapi.Route{
			Method: r.Method, Path: r.Path, Role: role,
			Summary: r.Summary, Description: r.Description,
			Idempotent:      r.Idempotent,
			Params:          r.Params,
			RequestExample:  r.RequestExample,
			ResponseExample: r.ResponseExample,
		})
	}
	return doc.Generate()
}
