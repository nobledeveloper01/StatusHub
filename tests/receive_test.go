package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapters"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/paystack"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/receive"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

const testSecretRef = "static://paystack-live"

type recordingNotifier struct {
	mu  sync.Mutex
	ids []string
}

func (n *recordingNotifier) Notify(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ids = append(n.ids, id)
}

func (n *recordingNotifier) seen() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.ids...)
}

type receiverHarness struct {
	store    *store.Memory
	server   *httptest.Server
	notifier *recordingNotifier
	endpoint domain.Endpoint
	path     string
}

func newReceiverHarness(t *testing.T) *receiverHarness {
	t.Helper()
	s := memStore(t)
	ctx := context.Background()

	ep := domain.Endpoint{
		ID:            domain.NewID(domain.PrefixEndpoint),
		TenantID:      tenantA,
		Provider:      "paystack",
		Environment:   domain.EnvLive,
		ReceiverToken: domain.NewToken(),
		SecretRef:     testSecretRef,
		AdapterName:   "paystack",
		Enabled:       true,
		CreatedAt:     time.Now().UTC(),
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "creating the endpoint")

	n := &recordingNotifier{}
	r := receive.New(receive.Options{
		Store:    s,
		Registry: adapters.New(),
		Secrets:  staticSecrets(testSecretRef, paystackSecret),
		Notifier: n,
	})
	srv := httptest.NewServer(r.Handler())
	t.Cleanup(srv.Close)

	return &receiverHarness{store: s, server: srv, notifier: n, endpoint: ep, path: ep.ReceiverPath(slugA)}
}

func (h *receiverHarness) post(t *testing.T, body []byte, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.server.URL+h.path, strings.NewReader(string(body)))
	mustNoErr(t, err, "building the request")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.server.Client().Do(req)
	mustNoErr(t, err, "sending the request")
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestReceiverPersistsBeforeAcknowledging(t *testing.T) {
	h := newReceiverHarness(t)
	body := fixture(t, "paystack", "charge.success.json")

	resp := h.post(t, body, map[string]string{paystack.Header: paystackSign(body, paystackSecret)})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var got struct {
		Received bool   `json:"received"`
		EventID  string `json:"event_id"`
	}
	mustNoErr(t, json.NewDecoder(resp.Body).Decode(&got), "decoding the response")
	if !got.Received || got.EventID == "" {
		t.Fatalf("response did not acknowledge the event: %+v", got)
	}

	// The event ID in the response must already resolve to a stored row. If
	// it does not, we told the provider it could forget an event we had not
	// written down — the one unrecoverable failure in the system (ADR-001).
	raw, err := h.store.GetRawEvent(context.Background(), tenantA, got.EventID)
	mustNoErr(t, err, "the acknowledged event was not durable")
	if string(raw.Body) != string(body) {
		t.Error("the stored body is not the bytes that arrived")
	}
	if !raw.SignatureValid {
		t.Error("a genuine signature was recorded as invalid")
	}
}

func TestReceiverStoresBodyVerbatim(t *testing.T) {
	h := newReceiverHarness(t)
	// Deliberately odd formatting. Signature verification is over these exact
	// bytes, so a round trip through a JSON decoder would make the stored
	// copy unverifiable later.
	body := []byte("{\n  \"event\" : \"charge.success\",\n  \"data\":{\"reference\":\"TXN-VERBATIM\",\"status\":\"success\",\"amount\":100,\"currency\":\"NGN\"}\n}")

	resp := h.post(t, body, map[string]string{paystack.Header: paystackSign(body, paystackSecret)})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got struct {
		EventID string `json:"event_id"`
	}
	mustNoErr(t, json.NewDecoder(resp.Body).Decode(&got), "decoding")

	raw, err := h.store.GetRawEvent(context.Background(), tenantA, got.EventID)
	mustNoErr(t, err, "fetching the raw event")
	if string(raw.Body) != string(body) {
		t.Fatalf("body was reformatted in storage:\n got: %q\nwant: %q", raw.Body, body)
	}
}

func TestReceiverStoresForgeriesAndNeverForwardsThem(t *testing.T) {
	h := newReceiverHarness(t)
	body := fixture(t, "paystack", "charge.success.json")

	resp := h.post(t, body, map[string]string{paystack.Header: paystackSign(body, "not-the-secret")})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	// The response must not explain what was wrong. A 401 that says which
	// part of the signature failed is an oracle a forger tunes against.
	var errBody map[string]string
	mustNoErr(t, json.NewDecoder(resp.Body).Decode(&errBody), "decoding the error")
	if errBody["error"] != "signature_verification_failed" || len(errBody) != 1 {
		t.Fatalf("the 401 leaked detail: %v", errBody)
	}

	// It is still stored. Discarding a forgery destroys the evidence of an
	// attack in progress (§10.1).
	failures, err := h.store.ListSignatureFailures(context.Background(), tenantA, h.endpoint.ID, time.Time{}, 10)
	mustNoErr(t, err, "listing signature failures")
	if len(failures) != 1 {
		t.Fatalf("the forgery was not retained: %d records", len(failures))
	}
	if failures[0].SignatureValid {
		t.Error("the stored forgery is not flagged")
	}
	if failures[0].SignatureError == "" {
		t.Error("the operator-facing reason was not recorded")
	}

	// And it is never handed to normalisation, which is what would eventually
	// forward it.
	if seen := h.notifier.seen(); len(seen) != 0 {
		t.Fatalf("a forgery was queued for normalisation: %v", seen)
	}
	pending, err := h.store.ListUnnormalised(context.Background(), 10)
	mustNoErr(t, err, "listing pending work")
	if len(pending) != 0 {
		t.Fatalf("a forgery is sitting in the normalisation queue: %d", len(pending))
	}
}

func TestReceiverRedactsSignatureHeaders(t *testing.T) {
	h := newReceiverHarness(t)
	body := fixture(t, "paystack", "charge.success.json")
	sig := paystackSign(body, paystackSecret)

	resp := h.post(t, body, map[string]string{
		paystack.Header: sig,
		"Authorization": "Bearer sk_live_should_never_be_stored",
		"User-Agent":    "Paystack/1.0",
	})
	var got struct {
		EventID string `json:"event_id"`
	}
	mustNoErr(t, json.NewDecoder(resp.Body).Decode(&got), "decoding")

	raw, err := h.store.GetRawEvent(context.Background(), tenantA, got.EventID)
	mustNoErr(t, err, "fetching the raw event")

	// A stored signature beside the exact body it signs is a replay kit for
	// anyone who reaches the database.
	if v := raw.Headers[strings.ToLower(paystack.Header)]; v != "[redacted]" {
		t.Errorf("signature header stored as %q", v)
	}
	if v := raw.Headers["authorization"]; v != "[redacted]" {
		t.Errorf("authorization header stored as %q", v)
	}
	// Recorded as present-and-redacted, not omitted, so an investigator can
	// tell a request that carried no signature from one whose signature we
	// chose not to keep.
	if _, present := raw.Headers["authorization"]; !present {
		t.Error("the redacted header was dropped entirely")
	}
	if raw.Headers["user-agent"] != "Paystack/1.0" {
		t.Errorf("a harmless header was not kept: %q", raw.Headers["user-agent"])
	}
}

func TestReceiverRejectsOversizedPayloads(t *testing.T) {
	h := newReceiverHarness(t)
	// Just over the 1 MB ceiling. The limit is enforced by reading one byte
	// past it rather than by trusting Content-Length, which is a claim the
	// caller makes.
	body := []byte(`{"data":{"reference":"X","padding":"` + strings.Repeat("A", 1<<20) + `"}}`)
	resp := h.post(t, body, map[string]string{paystack.Header: paystackSign(body, paystackSecret)})
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestReceiverURLComponentsAreAllChecked(t *testing.T) {
	h := newReceiverHarness(t)
	body := fixture(t, "paystack", "charge.success.json")
	sig := paystackSign(body, paystackSecret)
	headers := map[string]string{paystack.Header: sig}

	// A token is scoped to the exact endpoint it was issued for. Swapping any
	// component of the URL must fail, so a live token cannot be replayed
	// against the test environment or against another provider.
	for name, path := range map[string]string{
		"wrong environment": "/v1/hooks/" + slugA + "/paystack/test/" + h.endpoint.ReceiverToken,
		"wrong provider":    "/v1/hooks/" + slugA + "/flutterwave/live/" + h.endpoint.ReceiverToken,
		"wrong tenant":      "/v1/hooks/" + slugB + "/paystack/live/" + h.endpoint.ReceiverToken,
		"unknown token":     "/v1/hooks/" + slugA + "/paystack/live/tok_nonsense",
		"unknown tenant":    "/v1/hooks/nobody/paystack/live/" + h.endpoint.ReceiverToken,
	} {
		t.Run(name, func(t *testing.T) {
			saved := h.path
			h.path = path
			defer func() { h.path = saved }()
			resp := h.post(t, body, headers)
			// 404 everywhere, never 403: distinguishing them would let
			// someone enumerate which tenants and endpoints exist.
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", resp.StatusCode)
			}
		})
	}
}

func TestReceiverDisabledEndpointLooksLikeNoEndpoint(t *testing.T) {
	h := newReceiverHarness(t)
	ctx := context.Background()
	ep := h.endpoint
	ep.Enabled = false
	mustNoErr(t, h.store.UpdateEndpoint(ctx, tenantA, ep), "disabling the endpoint")

	body := fixture(t, "paystack", "charge.success.json")
	resp := h.post(t, body, map[string]string{paystack.Header: paystackSign(body, paystackSecret)})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 — a disabled endpoint must be indistinguishable from one that never existed", resp.StatusCode)
	}
}

func TestReceiverAcceptsBothSecretsDuringRotation(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(), SecretRef: testSecretRef,
		AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "creating the endpoint")

	const oldSecret = "sk_live_the_outgoing_one"
	r := receive.New(receive.Options{
		Store:    s,
		Registry: adapters.New(),
		// Newest first, previous second. Rotation with an overlap window is
		// what makes rotating a secret a routine act rather than an outage
		// (§8.2).
		Secrets: staticSecrets(testSecretRef, paystackSecret, oldSecret),
	})
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	body := fixture(t, "paystack", "charge.success.json")
	for name, secret := range map[string]string{"new secret": paystackSecret, "outgoing secret": oldSecret} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+ep.ReceiverPath(slugA), strings.NewReader(string(body)))
			mustNoErr(t, err, "building the request")
			req.Header.Set(paystack.Header, paystackSign(body, secret))
			resp, err := srv.Client().Do(req)
			mustNoErr(t, err, "sending")
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200 — rotation dropped an event", resp.StatusCode)
			}
		})
	}
}

func TestReceiverReadinessIgnoresTheDispatcher(t *testing.T) {
	h := newReceiverHarness(t)
	// Readiness for the receiver is exactly "can I write a raw event". A
	// shared probe would take the receiver out of rotation for a dispatcher
	// fault, losing the events persist-then-acknowledge exists to protect.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.server.URL+"/readyz", nil)
	mustNoErr(t, err, "building the readiness request")
	resp, err := h.server.Client().Do(req)
	mustNoErr(t, err, "probing readiness")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readiness = %d", resp.StatusCode)
	}
}

func TestReceiverQueuesForNormalisationOnlyAfterResponding(t *testing.T) {
	h := newReceiverHarness(t)
	body := fixture(t, "paystack", "charge.success.json")
	resp := h.post(t, body, map[string]string{paystack.Header: paystackSign(body, paystackSecret)})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got struct {
		EventID string `json:"event_id"`
	}
	mustNoErr(t, json.NewDecoder(resp.Body).Decode(&got), "decoding")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if seen := h.notifier.seen(); len(seen) == 1 && seen[0] == got.EventID {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the event was never handed to normalisation: %v", h.notifier.seen())
}
