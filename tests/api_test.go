package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapters"
	"github.com/nobledeveloper01/StatusHub/internal/api"
	"github.com/nobledeveloper01/StatusHub/internal/auth"
	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/secret"
	"github.com/nobledeveloper01/StatusHub/internal/store"
	"github.com/nobledeveloper01/StatusHub/internal/tunnel"
)

type apiHarness struct {
	store   *store.Memory
	keys    *auth.MemoryKeyStore
	server  *httptest.Server
	secrets *secret.Static
	sink    *sink
	tunnel  *tunnel.Hub

	ownerA    string
	ownerB    string
	engineerA string
	supportA  string
	readerA   string
}

func newAPIHarness(t *testing.T) *apiHarness {
	t.Helper()
	ctx := context.Background()
	s := memStore(t)
	keys := auth.NewMemoryKeyStore()

	secrets := secret.NewStatic()
	secrets.Set(testSecretRef, paystackSecret)
	secrets.Set(signingRef, signingSecret)

	guard, err := dispatch.NewGuard(dispatch.GuardOptions{AllowPrivate: true})
	mustNoErr(t, err, "building the guard")
	d, err := dispatch.New(dispatch.Options{
		Store: s, Secrets: secrets, Guard: guard, Shards: 8,
	})
	mustNoErr(t, err, "building the dispatcher")

	hub := tunnel.NewHub(tunnel.Options{MaxWait: 50 * time.Millisecond})
	srv := api.New(api.Options{
		Store: s, Keys: keys, Registry: adapters.New(), Dispatcher: d,
		Secrets: secrets, Guard: guard, Tunnel: hub, BaseURL: "https://hooks.statushub.test",
	})

	h := &apiHarness{store: s, keys: keys, secrets: secrets, sink: newSink(t), tunnel: hub}
	h.server = httptest.NewServer(srv.Handler())
	t.Cleanup(h.server.Close)

	issue := func(tenant string, role auth.Role) string {
		plain, key, err := auth.Issue(tenant, domain.EnvLive, role, string(role), 0)
		mustNoErr(t, err, "issuing a key")
		mustNoErr(t, keys.PutKey(ctx, key), "storing the key")
		return plain
	}
	h.ownerA = issue(tenantA, auth.RoleOwner)
	h.ownerB = issue(tenantB, auth.RoleOwner)
	h.engineerA = issue(tenantA, auth.RoleEngineer)
	h.supportA = issue(tenantA, auth.RoleSupport)
	h.readerA = issue(tenantA, auth.RoleReadOnly)
	return h
}

// apiResponse is what the harness hands back.
//
// A value rather than *http.Response, because the helper has already read and
// closed the body — and handing out a response whose body is closed invites
// somebody to read it, and makes every call site look like a leak to anything
// tracking response lifetimes.
type apiResponse struct {
	StatusCode int
	Header     http.Header
}

func (h *apiHarness) do(t *testing.T, key, method, path string, body any) (apiResponse, map[string]any) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		mustNoErr(t, err, "marshalling")
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.server.URL+path, rdr)
	mustNoErr(t, err, "building the request")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.server.Client().Do(req)
	mustNoErr(t, err, "sending")

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	// Closed here rather than in a Cleanup: the body is fully read above, and
	// deferring it to the end of the test leaks a connection per request in
	// the tests that make dozens.
	_ = resp.Body.Close()
	return apiResponse{StatusCode: resp.StatusCode, Header: resp.Header}, out
}

// destinationURL is a resolvable https URL for the harness, whose guard has
// AllowPrivate set so the loopback address is acceptable. A public hostname
// would make every one of these tests depend on DNS.
const destinationURL = "https://localhost:9443/hooks"

func TestAPIRejectsUnauthenticatedRequests(t *testing.T) {
	h := newAPIHarness(t)
	for _, path := range []string{"/v1/endpoints", "/v1/destinations", "/v1/events", "/v1/keys", "/v1/audit/verify"} {
		resp, body := h.do(t, "", http.MethodGet, path, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without a key = %d, want 401", path, resp.StatusCode)
		}
		// The 401 must say nothing. Distinguishing "no key" from "unknown
		// key" from "revoked key" tells a caller which of their stolen keys
		// are real.
		if body["error"] != "unauthorised" || len(body) != 1 {
			t.Errorf("GET %s leaked detail: %v", path, body)
		}
	}
}

func TestAPIRejectsEveryBadKeyIdentically(t *testing.T) {
	h := newAPIHarness(t)
	ctx := context.Background()

	revokedPlain, revoked, err := auth.Issue(tenantA, domain.EnvLive, auth.RoleOwner, "revoked", 0)
	mustNoErr(t, err, "issuing")
	mustNoErr(t, h.keys.PutKey(ctx, revoked), "storing")
	mustNoErr(t, h.keys.RevokeKey(ctx, tenantA, revoked.ID, time.Now().UTC()), "revoking")

	expiredPlain, expired, err := auth.Issue(tenantA, domain.EnvLive, auth.RoleOwner, "expired", time.Nanosecond)
	mustNoErr(t, err, "issuing")
	mustNoErr(t, h.keys.PutKey(ctx, expired), "storing")
	time.Sleep(2 * time.Millisecond)

	testEnvPlain, testEnv, err := auth.Issue(tenantA, domain.EnvTest, auth.RoleOwner, "test env", 0)
	mustNoErr(t, err, "issuing")
	mustNoErr(t, h.keys.PutKey(ctx, testEnv), "storing")

	for name, key := range map[string]string{
		"garbage":     "not-a-key",
		"wrong shape": "sh_live_",
		"unknown":     "sh_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"revoked":     revokedPlain,
		"expired":     expiredPlain,
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := h.do(t, key, http.MethodGet, "/v1/endpoints", nil)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if body["error"] != "unauthorised" {
				t.Errorf("body = %v", body)
			}
		})
	}

	// A test key does work — against test resources. It simply cannot be used
	// where a live key is required, which is checked per-operation.
	resp, _ := h.do(t, testEnvPlain, http.MethodGet, "/v1/endpoints", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("a valid test key was refused entirely: %d", resp.StatusCode)
	}
}

func TestAPITenantsCannotSeeEachOther(t *testing.T) {
	// The blocking gate, at the HTTP layer this time (§8.1).
	h := newAPIHarness(t)

	resp, created := h.do(t, h.ownerA, http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "paystack", "environment": "live", "secret_ref": testSecretRef,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating an endpoint = %d: %v", resp.StatusCode, created)
	}
	endpointID, _ := created["id"].(string)

	resp, dest := h.do(t, h.ownerA, http.MethodPost, "/v1/destinations", map[string]any{
		"url": destinationURL, "signing_secret_ref": signingRef,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating a destination = %d: %v", resp.StatusCode, dest)
	}
	destID, _ := dest["id"].(string)

	// Tenant B, with a perfectly valid key of their own, gets 404 for every
	// one of tenant A's resources. Never 403 — a 403 confirms the resource
	// exists, which is a working cross-tenant enumeration oracle.
	for name, path := range map[string]string{
		"endpoint":           "/v1/endpoints/" + endpointID,
		"destination":        "/v1/destinations/" + destID,
		"signature failures": "/v1/endpoints/" + endpointID + "/signature-failures",
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := h.do(t, h.ownerB, http.MethodGet, path, nil)
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("tenant B reading A's %s = %d, want 404: %v", name, resp.StatusCode, body)
			}
		})
	}

	// And their lists are empty rather than filtered-with-a-hint.
	_, list := h.do(t, h.ownerB, http.MethodGet, "/v1/endpoints", nil)
	if eps, _ := list["endpoints"].([]any); len(eps) != 0 {
		t.Errorf("tenant B sees %d of tenant A's endpoints", len(eps))
	}
}

func TestAPIRolesAreEnforced(t *testing.T) {
	h := newAPIHarness(t)

	// A read-only key cannot create anything.
	resp, _ := h.do(t, h.readerA, http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "paystack", "environment": "live", "secret_ref": testSecretRef,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("read-only creating an endpoint = %d, want 403", resp.StatusCode)
	}

	// Support can replay but cannot change an adapter. That split is the
	// whole reason the role exists: replaying is what support staff need
	// hourly, and an adapter edit silently changes what every future event
	// means.
	resp, _ = h.do(t, h.supportA, http.MethodPost, "/v1/adapters", map[string]any{
		"config": json.RawMessage(acmeBankConfig),
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("support uploading an adapter = %d, want 403", resp.StatusCode)
	}
	resp, _ = h.do(t, h.supportA, http.MethodGet, "/v1/events", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("support searching events = %d, want 200", resp.StatusCode)
	}

	// Only an owner can mint keys, because a key that can issue keys can
	// escalate to any role.
	resp, _ = h.do(t, h.engineerA, http.MethodPost, "/v1/keys", map[string]any{
		"name": "escalation", "role": "owner", "environment": "live",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("engineer issuing a key = %d, want 403", resp.StatusCode)
	}
}

func TestAPINeverReturnsASecret(t *testing.T) {
	h := newAPIHarness(t)

	resp, created := h.do(t, h.ownerA, http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "paystack", "environment": "live", "secret_ref": testSecretRef,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := json.Marshal(created)
	// The reference may appear. The secret itself must not, anywhere, ever —
	// otherwise every API key is as dangerous as the signing secret.
	if bytes.Contains(body, []byte(paystackSecret)) {
		t.Fatalf("the endpoint response contained the signing secret: %s", body)
	}
	if created["secret_ref"] != testSecretRef {
		t.Errorf("secret_ref = %v", created["secret_ref"])
	}
	// And the receiver URL is complete enough to paste straight into the
	// provider's dashboard, which is the entire integration.
	url, _ := created["receiver_url"].(string)
	if url == "" || !bytes.Contains([]byte(url), []byte("/v1/hooks/acme/paystack/live/tok_")) {
		t.Errorf("receiver_url = %q", url)
	}
}

func TestAPIKeyIsShownExactlyOnce(t *testing.T) {
	h := newAPIHarness(t)
	resp, created := h.do(t, h.ownerA, http.MethodPost, "/v1/keys", map[string]any{
		"name": "ci", "role": "engineer", "environment": "live",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d: %v", resp.StatusCode, created)
	}
	plaintext, _ := created["key"].(string)
	if plaintext == "" {
		t.Fatal("no key returned")
	}

	// It works.
	resp, _ = h.do(t, plaintext, http.MethodGet, "/v1/endpoints", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the freshly-issued key does not work: %d", resp.StatusCode)
	}

	// And it never appears again.
	_, list := h.do(t, h.ownerA, http.MethodGet, "/v1/keys", nil)
	b, _ := json.Marshal(list)
	if bytes.Contains(b, []byte(plaintext)) {
		t.Fatalf("the key listing returned a usable key: %s", b)
	}
}

func TestAPIRefusesToRevokeTheKeyInUse(t *testing.T) {
	// Locking a tenant out of their own account with no way back in is worse
	// than being technically correct about what revoke means.
	h := newAPIHarness(t)
	_, list := h.do(t, h.ownerA, http.MethodGet, "/v1/keys", nil)
	keys, _ := list["keys"].([]any)
	var ownerKeyID string
	for _, k := range keys {
		m, _ := k.(map[string]any)
		if m["role"] == "owner" && m["name"] == "owner" {
			ownerKeyID, _ = m["id"].(string)
		}
	}
	if ownerKeyID == "" {
		t.Fatal("could not find the owner key")
	}

	resp, body := h.do(t, h.ownerA, http.MethodDelete, "/v1/keys/"+ownerKeyID, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("revoking the key in use = %d, want 400: %v", resp.StatusCode, body)
	}
}

func TestAPIRefusesDestinationsThatWouldReachInside(t *testing.T) {
	h := newAPIHarness(t)
	// AllowPrivate is on in this harness so the test sink is reachable, so
	// the assertion here is on the scheme and shape checks, which apply
	// regardless. The address rules have their own test.
	for _, url := range []string{
		"http://acme.example.com/hooks",            // not https
		"https://user:pass@acme.example.com/hooks", // embedded credentials
		"ftp://acme.example.com/hooks",             //
	} {
		resp, _ := h.do(t, h.ownerA, http.MethodPost, "/v1/destinations", map[string]any{
			"url": url, "signing_secret_ref": signingRef,
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("destination %q = %d, want 400", url, resp.StatusCode)
		}
	}
}

func TestAPIRefusesAnUnresolvableSecretReference(t *testing.T) {
	// A reference that does not resolve produces an endpoint that rejects
	// every event as unverified, which in the dashboard looks exactly like an
	// attack.
	h := newAPIHarness(t)
	resp, body := h.do(t, h.ownerA, http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "paystack", "environment": "live", "secret_ref": "static://nothing-here",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %v", resp.StatusCode, body)
	}
}

func TestAPIAdapterUploadRunsTheSamplesFirst(t *testing.T) {
	h := newAPIHarness(t)

	// A sample the adapter cannot read blocks the upload: the customer
	// supplied it as an example of what the provider sends.
	resp, body := h.do(t, h.engineerA, http.MethodPost, "/v1/adapters", map[string]any{
		"config":  json.RawMessage(acmeBankConfig),
		"samples": []map[string]string{{"name": "broken", "body": `{"nope":true}`}},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an adapter that could not read its own sample was accepted: %d %v", resp.StatusCode, body)
	}

	// A good one is accepted, and the response carries the dry run.
	resp, body = h.do(t, h.engineerA, http.MethodPost, "/v1/adapters", map[string]any{
		"config":  json.RawMessage(acmeBankConfig),
		"samples": []map[string]string{{"name": "success", "body": acmePayload}},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d: %v", resp.StatusCode, body)
	}

	// And it is now usable on an endpoint.
	resp, ep := h.do(t, h.engineerA, http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "acme-bank", "environment": "live",
		"adapter": "acme-bank", "secret_ref": testSecretRef,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("using the uploaded adapter = %d: %v", resp.StatusCode, ep)
	}
}

func TestAPIAdapterCannotShadowABuiltIn(t *testing.T) {
	h := newAPIHarness(t)
	cfg := bytes.Replace([]byte(acmeBankConfig), []byte(`"name": "acme-bank"`), []byte(`"name": "paystack"`), 1)
	resp, _ := h.do(t, h.engineerA, http.MethodPost, "/v1/adapters", map[string]any{
		"config": json.RawMessage(cfg),
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("a tenant redefined a built-in adapter: %d", resp.StatusCode)
	}
}

func TestAPIAdapterInUseCannotBeDeleted(t *testing.T) {
	// An endpoint pointing at a deleted adapter would store every incoming
	// webhook flagged invalid and forward none of them — which looks exactly
	// like an attack in the dashboard.
	h := newAPIHarness(t)
	resp, _ := h.do(t, h.engineerA, http.MethodPost, "/v1/adapters", map[string]any{
		"config": json.RawMessage(acmeBankConfig), "samples": []map[string]string{{"body": acmePayload}},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("uploading = %d", resp.StatusCode)
	}
	resp, _ = h.do(t, h.engineerA, http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "acme-bank", "environment": "live", "adapter": "acme-bank", "secret_ref": testSecretRef,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating the endpoint = %d", resp.StatusCode)
	}

	resp, body := h.do(t, h.engineerA, http.MethodDelete, "/v1/adapters/acme-bank", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("deleting an adapter still in use = %d, want 409: %v", resp.StatusCode, body)
	}
}

func TestAPITokenRotationChangesOnlyTheToken(t *testing.T) {
	h := newAPIHarness(t)
	_, created := h.do(t, h.ownerA, http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "paystack", "environment": "live", "secret_ref": testSecretRef,
	})
	id, _ := created["id"].(string)
	before, _ := created["receiver_url"].(string)

	resp, rotated := h.do(t, h.ownerA, http.MethodPost, "/v1/endpoints/"+id+"/rotate-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotating = %d: %v", resp.StatusCode, rotated)
	}
	ep, _ := rotated["endpoint"].(map[string]any)
	after, _ := ep["receiver_url"].(string)

	if after == before {
		t.Fatal("the token did not change")
	}
	// The URL shape is unchanged, so rotating is a one-line edit in the
	// provider's dashboard rather than a reconfiguration.
	if !bytes.Contains([]byte(after), []byte("/v1/hooks/acme/paystack/live/tok_")) {
		t.Errorf("the URL structure changed: %q", after)
	}

	// And the previous token is not echoed anywhere, including the audit
	// trail — it is still a working URL component if the rotation is undone.
	_, auditBody := h.do(t, h.ownerA, http.MethodGet, "/v1/audit", nil)
	b, _ := json.Marshal(auditBody)
	if bytes.Contains(b, []byte(before)) {
		t.Errorf("the previous receiver URL was recorded in the audit trail")
	}
}

func TestAPIAuditTrailRecordsEveryWrite(t *testing.T) {
	h := newAPIHarness(t)
	h.do(t, h.ownerA, http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "paystack", "environment": "live", "secret_ref": testSecretRef,
	})
	h.do(t, h.ownerA, http.MethodPost, "/v1/destinations", map[string]any{
		"url": destinationURL, "signing_secret_ref": signingRef,
	})

	_, body := h.do(t, h.ownerA, http.MethodGet, "/v1/audit", nil)
	records, _ := body["records"].([]any)
	if len(records) < 2 {
		t.Fatalf("%d audit records, want at least 2", len(records))
	}
	// Recorded against the key that made the change, so "who changed this"
	// has an answer (§6.4).
	first, _ := records[0].(map[string]any)
	actor, _ := first["actor"].(map[string]any)
	if actor["type"] != "api_key" || actor["id"] == "" {
		t.Errorf("audit record has no usable actor: %v", actor)
	}

	// And the chain verifies.
	resp, proof := h.do(t, h.ownerA, http.MethodGet, "/v1/audit/verify", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chain verification = %d: %v", resp.StatusCode, proof)
	}
	if proof["intact"] != true {
		t.Errorf("chain is not intact: %v", proof)
	}
}

func TestAPIEventExplorerShowsWhatWasDelivered(t *testing.T) {
	h := newAPIHarness(t)
	ctx := context.Background()

	ev := domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "paystack",
		EventType: domain.EventPaymentCompleted, TransactionRef: "TXN-EXPLORE",
		Status: domain.StatusSuccess, AmountMinor: 5000000, Currency: "NGN",
		OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(), MappingComplete: true,
	}
	mustNoErr(t, h.store.PutCanonicalEvent(ctx, ev), "storing the event")

	_, body := h.do(t, h.readerA, http.MethodGet, "/v1/events?transaction_ref=TXN-EXPLORE", nil)
	events, _ := body["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("%d events found, want 1", len(events))
	}
	got, _ := events[0].(map[string]any)
	// The explorer renders the same shape the destination receives, so there
	// is never a "but the delivered version looked different" conversation.
	if got["transaction_ref"] != "TXN-EXPLORE" || got["status"] != "success" {
		t.Errorf("event = %v", got)
	}
	if fmt.Sprintf("%v", got["amount_minor"]) != "5e+06" && fmt.Sprintf("%v", got["amount_minor"]) != "5000000" {
		t.Errorf("amount_minor = %v", got["amount_minor"])
	}
}

func TestAPIRawPayloadAccessIsAudited(t *testing.T) {
	// Raw bodies are the most sensitive thing StatusHub holds, so reading one
	// is an event in its own right (§8.4).
	h := newAPIHarness(t)
	ctx := context.Background()

	raw := domain.RawEvent{
		ID: domain.NewID(domain.PrefixRawEvent), TenantID: tenantA, EndpointID: "ep_x",
		Provider: "paystack", Body: []byte(`{"data":{"reference":"TXN-RAW"}}`),
		BodySHA256: "hash", SignatureValid: true, ReceivedAt: time.Now().UTC(),
	}
	mustNoErr(t, h.store.PutRawEvent(ctx, raw), "storing the raw event")
	ev := domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, RawEventID: raw.ID,
		Provider: "paystack", EventType: domain.EventPaymentCompleted,
		TransactionRef: "TXN-RAW", Status: domain.StatusSuccess, OccurredAt: time.Now().UTC(),
	}
	mustNoErr(t, h.store.PutCanonicalEvent(ctx, ev), "storing the event")

	// Read-only cannot see raw bodies at all.
	resp, _ := h.do(t, h.readerA, http.MethodGet, "/v1/events/"+ev.ID+"/raw", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("read-only reading a raw payload = %d, want 403", resp.StatusCode)
	}

	resp, body := h.do(t, h.supportA, http.MethodGet, "/v1/events/"+ev.ID+"/raw", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("support reading a raw payload = %d: %v", resp.StatusCode, body)
	}

	_, auditBody := h.do(t, h.ownerA, http.MethodGet, "/v1/audit", nil)
	records, _ := auditBody["records"].([]any)
	var sawRead bool
	for _, r := range records {
		m, _ := r.(map[string]any)
		if m["event_type"] == "raw_payload.read" {
			sawRead = true
		}
	}
	if !sawRead {
		t.Fatal("reading a raw payload was not audited")
	}
}

func TestAPIRejectsUnknownRequestFields(t *testing.T) {
	// A caller who typed secretRef instead of secret_ref should be told, not
	// have the field silently ignored and get an endpoint with no secret.
	h := newAPIHarness(t)
	resp, _ := h.do(t, h.ownerA, http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "paystack", "environment": "live", "secretRef": testSecretRef,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unknown field was accepted: %d", resp.StatusCode)
	}
}
