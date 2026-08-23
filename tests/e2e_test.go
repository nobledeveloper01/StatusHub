package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapters"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/paystack"
	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/normalise"
	"github.com/nobledeveloper01/StatusHub/internal/receive"
	"github.com/nobledeveloper01/StatusHub/internal/secret"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

// TestEndToEnd is the product in one test.
//
// A provider POSTs a signed payload; StatusHub verifies it, stores the bytes,
// answers 200, normalises off the request path, and forwards one canonical
// shape to the customer's endpoint with a signature they can verify. Every
// other test here checks one link in that chain; this one checks that the
// chain exists.
func TestEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := memStore(t)
	customer := newSink(t)

	secrets := secret.NewStatic()
	secrets.Set(testSecretRef, paystackSecret)
	secrets.Set(signingRef, signingSecret)
	secrets.Set(normalise.SaltRef(tenantA), "a-per-tenant-salt")

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true, CreatedAt: time.Now().UTC(),
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "creating the endpoint")

	mustNoErr(t, s.CreateDestination(ctx, domain.Destination{
		ID: domain.NewID(domain.PrefixDestination), TenantID: tenantA, Name: "ledger",
		URL: customer.server.URL, SigningSecretRef: signingRef,
		RetryPolicy: domain.DefaultRetryPolicy(), Enabled: true, CreatedAt: time.Now().UTC(),
	}), "creating the destination")

	guard, err := dispatch.NewGuard(dispatch.GuardOptions{AllowPrivate: true})
	mustNoErr(t, err, "building the guard")
	dispatcher, err := dispatch.New(dispatch.Options{
		Store: s, Secrets: secrets, Guard: guard, Shards: 8,
	})
	mustNoErr(t, err, "building the dispatcher")

	normaliser := normalise.New(normalise.Options{
		Store: s, Registry: adapters.New(), Secrets: secrets, Enqueuer: dispatcher,
	})
	normWorker := normalise.NewWorker(normalise.WorkerOptions{
		Normaliser: normaliser, Interval: 20 * time.Millisecond,
	})
	go normWorker.Run(ctx)
	defer normWorker.Stop()

	dispWorker := dispatch.NewWorker(dispatch.WorkerOptions{
		Dispatcher: dispatcher, Interval: 20 * time.Millisecond,
	})
	go dispWorker.Run(ctx)
	defer dispWorker.Stop()

	receiver := receive.New(receive.Options{
		Store: s, Registry: adapters.New(), Secrets: secrets, Notifier: normWorker,
	})
	hooks := httptest.NewServer(receiver.Handler())
	defer hooks.Close()

	// --- the provider POSTs ---

	body := fixture(t, "paystack", "charge.success.json")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		hooks.URL+ep.ReceiverPath(slugA), strings.NewReader(string(body)))
	mustNoErr(t, err, "building the provider request")
	req.Header.Set(paystack.Header, paystackSign(body, paystackSecret))

	start := time.Now()
	resp, err := hooks.Client().Do(req)
	mustNoErr(t, err, "sending the provider request")
	defer func() { _ = resp.Body.Close() }()
	ack := time.Since(start)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the provider got %d", resp.StatusCode)
	}
	// The SLO is 50 ms p99 against a real database. Against the in-memory
	// store this is only a sanity bound — but a regression that made the
	// acknowledgement synchronous with delivery would blow even this.
	if ack > 2*time.Second {
		t.Errorf("the provider waited %s for its 200", ack)
	}

	// --- the customer receives ---

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && customer.count() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if customer.count() != 1 {
		t.Fatalf("%d deliveries reached the customer", customer.count())
	}

	got := customer.all()[0]
	if got.Provider != "paystack" || got.TransactionRef != "TXN-2026-08-11-8842" {
		t.Errorf("payload = %+v", got)
	}
	if got.Status != "success" || got.EventType != "payment.completed" {
		t.Errorf("status/type = %s / %s", got.Status, got.EventType)
	}
	if got.AmountMinor != 5000000 || got.Currency != "NGN" {
		t.Errorf("amount = %d %s", got.AmountMinor, got.Currency)
	}
	if !got.MappingComplete {
		t.Error("mapping_complete = false on a fully-mapped payload")
	}
	// The customer's email must not have travelled. The hash is enough to
	// correlate two events as one person without us holding who they are.
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "tunde@example.com") {
		t.Fatalf("the customer email was forwarded: %s", raw)
	}
	if got.Customer == nil || !strings.HasPrefix(got.Customer.RefHash, "sha256:") {
		t.Errorf("customer ref = %+v", got.Customer)
	}
	// Nothing the provider sent was dropped.
	if got.ProviderExtra["data.authorization.last4"] != "4081" {
		t.Errorf("provider_extra lost a field: %v", got.ProviderExtra)
	}

	customer.mu.Lock()
	header := customer.headers[0].Get(dispatch.SignatureHeader)
	delivered := customer.bodies[0]
	idempotency := customer.headers[0].Get("Idempotency-Key")
	customer.mu.Unlock()

	// The signature the customer verifies with the published helper.
	mustNoErr(t, dispatch.Verify(signingSecret, delivered, header, time.Now(), 5*time.Minute),
		"the delivered signature must verify with the same function the SDKs use")
	if idempotency != got.EventID {
		t.Errorf("Idempotency-Key = %q, want the event ID", idempotency)
	}

	// --- and the trail is complete ---

	events, err := s.QueryEvents(ctx, tenantA, store.EventQuery{})
	mustNoErr(t, err, "querying events")
	if len(events) != 1 {
		t.Fatalf("%d canonical events stored", len(events))
	}
	stored, err := s.GetRawEvent(ctx, tenantA, events[0].RawEventID)
	mustNoErr(t, err, "fetching the raw event")
	if string(stored.Body) != string(body) {
		t.Error("the stored raw body is not the bytes the provider sent")
	}

	proof, err := s.VerifyChain(ctx, tenantA)
	mustNoErr(t, err, "verifying the audit chain")
	if !proof.Intact {
		t.Fatalf("audit chain broken: %+v", proof)
	}
	// received, normalised, forwarded — the three states an auditor asks
	// about (§9).
	records, err := s.ListAudit(ctx, tenantA, time.Time{}, 50)
	mustNoErr(t, err, "listing the audit trail")
	seen := map[domain.AuditEventType]bool{}
	for _, r := range records {
		seen[r.EventType] = true
	}
	for _, want := range []domain.AuditEventType{
		domain.AuditEventReceived, domain.AuditEventNormalised, domain.AuditEventForwarded,
	} {
		if !seen[want] {
			t.Errorf("the audit trail has no %s record", want)
		}
	}
}

// TestEndToEndSurvivesTheCustomerBeingDown is the promise the product is sold
// on: a customer's outage costs them nothing.
func TestEndToEndSurvivesTheCustomerBeingDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := memStore(t)
	customer := newSink(t)
	customer.setResponder(func(int) (int, string) { return http.StatusServiceUnavailable, "deploying" })

	secrets := secret.NewStatic()
	secrets.Set(testSecretRef, paystackSecret)
	secrets.Set(signingRef, signingSecret)
	secrets.Set(normalise.SaltRef(tenantA), "salt")

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "endpoint")
	mustNoErr(t, s.CreateDestination(ctx, domain.Destination{
		ID: domain.NewID(domain.PrefixDestination), TenantID: tenantA, URL: customer.server.URL,
		SigningSecretRef: signingRef,
		RetryPolicy: domain.RetryPolicy{
			Backoff: []time.Duration{0, 10 * time.Millisecond, 10 * time.Millisecond},
			Timeout: time.Second,
		},
		Enabled: true,
	}), "destination")

	guard, _ := dispatch.NewGuard(dispatch.GuardOptions{AllowPrivate: true})
	dispatcher, err := dispatch.New(dispatch.Options{Store: s, Secrets: secrets, Guard: guard, Shards: 8})
	mustNoErr(t, err, "dispatcher")
	normaliser := normalise.New(normalise.Options{
		Store: s, Registry: adapters.New(), Secrets: secrets, Enqueuer: dispatcher,
	})
	normWorker := normalise.NewWorker(normalise.WorkerOptions{Normaliser: normaliser, Interval: 10 * time.Millisecond})
	go normWorker.Run(ctx)
	defer normWorker.Stop()
	dispWorker := dispatch.NewWorker(dispatch.WorkerOptions{Dispatcher: dispatcher, Interval: 10 * time.Millisecond})
	go dispWorker.Run(ctx)
	defer dispWorker.Stop()

	receiver := receive.New(receive.Options{
		Store: s, Registry: adapters.New(), Secrets: secrets, Notifier: normWorker,
	})
	hooks := httptest.NewServer(receiver.Handler())
	defer hooks.Close()

	// Five events arrive while the customer is deploying.
	for i := 0; i < 5; i++ {
		body := []byte(fmt.Sprintf(
			`{"event":"charge.success","data":{"reference":"TXN-DOWN-%d","status":"success","amount":100,"currency":"NGN","paid_at":"2026-08-11T09:14:31.000Z"}}`, i))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			hooks.URL+ep.ReceiverPath(slugA), strings.NewReader(string(body)))
		mustNoErr(t, err, "building")
		req.Header.Set(paystack.Header, paystackSign(body, paystackSecret))
		resp, err := hooks.Client().Do(req)
		mustNoErr(t, err, "sending")
		// Every one is acknowledged. The provider never learns that the
		// customer is down, so it never retries and never gives up.
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("event %d got %d while the customer was down", i, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}

	// All five are stored and normalised regardless.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		events, err := s.QueryEvents(ctx, tenantA, store.EventQuery{})
		mustNoErr(t, err, "querying")
		if len(events) == 5 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	events, err := s.QueryEvents(ctx, tenantA, store.EventQuery{})
	mustNoErr(t, err, "querying")
	if len(events) != 5 {
		t.Fatalf("%d events survived the customer's outage, want 5", len(events))
	}

	// The customer comes back. Everything replays.
	customer.setResponder(func(int) (int, string) { return http.StatusOK, "" })
	res, err := dispatcher.Replay(ctx, tenantA, dispatch.ReplayRequest{Filter: &store.EventQuery{}})
	mustNoErr(t, err, "replaying")
	if res.Queued != 5 {
		t.Fatalf("replay queued %d, want 5", res.Queued)
	}

	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		delivered := map[string]bool{}
		for _, p := range customer.all() {
			delivered[p.TransactionRef] = true
		}
		if len(delivered) == 5 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("only %d distinct transactions reached the customer after recovery", len(customer.all()))
}
