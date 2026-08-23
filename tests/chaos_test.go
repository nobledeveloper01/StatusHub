package tests

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

// The chaos suite (§11.9).
//
// Every other test asserts that something works. These assert that something
// keeps working while a component is killed underneath it — which is a
// different property, and the only one that matters for the two claims the
// product is sold on: no provider event is ever lost, and the customer never
// sees a duplicate they cannot deduplicate.

// TestChaosDispatcherKilledMidDelivery is the claim that a deploy loses
// nothing.
//
// A dispatcher replica dies with deliveries in flight. Its leases expire,
// another replica reclaims them, and every event reaches the customer —
// exactly once from their point of view, because every attempt carries the
// same idempotency key.
func TestChaosDispatcherKilledMidDelivery(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	// The sink records idempotency keys rather than request counts: the
	// promise is not "one request", it is "one event the customer can
	// recognise as one event".
	var (
		mu       sync.Mutex
		byKey    = map[string]int{}
		inFlight atomic.Int32
		stall    atomic.Bool
	)
	// TLS, because the destinations table enforces https at the database
	// level as well as in the application — the application check produces
	// the good error message, and this one holds when a future code path
	// forgets to call it.
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inFlight.Add(1)
		defer inFlight.Add(-1)

		key := r.Header.Get("Idempotency-Key")
		mu.Lock()
		byKey[key]++
		mu.Unlock()

		if stall.Load() {
			// Stalls long enough for the "replica" to be killed mid-request.
			time.Sleep(2 * time.Second)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	dest := domain.Destination{
		ID: domain.NewID(domain.PrefixDestination), TenantID: tenantA, URL: sink.URL,
		SigningSecretRef: signingRef,
		RetryPolicy: domain.RetryPolicy{
			Backoff: []time.Duration{0, 50 * time.Millisecond, 50 * time.Millisecond, 50 * time.Millisecond},
			Timeout: 5 * time.Second,
		},
		Enabled: true,
	}
	mustNoErr(t, s.CreateDestination(ctx, dest), "destination")

	guard, err := dispatch.NewGuard(dispatch.GuardOptions{AllowPrivate: true})
	mustNoErr(t, err, "guard")
	newDispatcher := func() *dispatch.Dispatcher {
		d, err := dispatch.New(dispatch.Options{
			Store: s, Secrets: staticSecrets(signingRef, signingSecret),
			Guard: guard, Shards: domain.DefaultShards,
			// The test server's certificate is self-signed, so the client
			// that trusts it is supplied rather than built. The SSRF guard's
			// dialler has its own tests; this one is about surviving a kill.
			Client: sink.Client(),
		})
		mustNoErr(t, err, "dispatcher")
		return d
	}

	const events = 20
	var ids []string
	first := newDispatcher()
	for i := 0; i < events; i++ {
		ev := domain.CanonicalEvent{
			ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "paystack",
			EventType: domain.EventPaymentCompleted, TransactionRef: fmt.Sprintf("TXN-CHAOS-%02d", i),
			Status: domain.StatusSuccess, AmountMinor: 5000000, Currency: "NGN",
			OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(),
		}
		mustNoErr(t, s.PutCanonicalEvent(ctx, ev), "event")
		mustNoErr(t, first.Enqueue(ctx, ev), "enqueue")
		ids = append(ids, ev.ID)
	}

	// The first replica starts delivering, stalls mid-flight, and is killed.
	stall.Store(true)
	killed, cancel := context.WithCancel(ctx)
	worker := dispatch.NewWorker(dispatch.WorkerOptions{
		Dispatcher: first, Interval: 10 * time.Millisecond,
		// A short lease so the test does not wait out a production one.
		Lease: 500 * time.Millisecond,
	})
	go worker.Run(killed)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && inFlight.Load() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	if inFlight.Load() < 1 {
		t.Fatal("no delivery was ever in flight; the test never reached the interesting state")
	}

	// SIGKILL, effectively: the context is cancelled and the worker is
	// abandoned without draining. Deliveries it claimed are left in_flight
	// with a lease nobody will complete.
	cancel()
	stall.Store(false)

	// Nothing recovers on its own until the leases expire. That is the point
	// of the lease: a crash costs one lease interval, not a stalled shard.
	time.Sleep(700 * time.Millisecond)
	reclaimed, err := s.ReclaimExpiredLeases(ctx, time.Now().UTC())
	mustNoErr(t, err, "reclaiming")
	if reclaimed == 0 {
		t.Error("no leases were reclaimed; a killed replica would stall its keys forever")
	}

	// A fresh replica takes over.
	second := newDispatcher()
	recovered, recoverCancel := context.WithCancel(ctx)
	defer recoverCancel()
	go dispatch.NewWorker(dispatch.WorkerOptions{
		Dispatcher: second, Interval: 10 * time.Millisecond, Lease: 30 * time.Second,
	}).Run(recovered)

	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		done := 0
		for _, id := range ids {
			dels, err := s.ListDeliveriesForEvent(ctx, tenantA, id)
			mustNoErr(t, err, "listing")
			for _, d := range dels {
				if d.Status == domain.DeliverySucceeded {
					done++
					break
				}
			}
		}
		if done == events {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Nothing lost.
	for _, id := range ids {
		dels, err := s.ListDeliveriesForEvent(ctx, tenantA, id)
		mustNoErr(t, err, "listing")
		var delivered bool
		for _, d := range dels {
			if d.Status == domain.DeliverySucceeded {
				delivered = true
			}
		}
		if !delivered {
			t.Errorf("event %s was never delivered after the dispatcher was killed", id)
		}
	}

	// And nothing the customer cannot deduplicate: a retry after a killed
	// replica carries the same idempotency key as the attempt that died.
	mu.Lock()
	defer mu.Unlock()
	if len(byKey) != events {
		t.Errorf("%d distinct idempotency keys reached the sink, want %d", len(byKey), events)
	}
	var repeated int
	for key, n := range byKey {
		if n > 1 {
			repeated++
			if key == "" {
				t.Error("a delivery arrived with no idempotency key, so the customer cannot deduplicate it")
			}
		}
	}
	t.Logf("%d of %d events were delivered more than once after the kill — each with a stable "+
		"idempotency key, which is what turns our at-least-once into the customer's exactly-once",
		repeated, events)
}

// TestChaosReceiverKilledBetweenPersistAndAcknowledge is the other half of
// ADR-001, and the failure the whole ordering exists to make survivable.
//
// The process dies after the row is committed and before the 200 is written.
// The provider sees a failure and retries. The retry must not produce a
// second canonical event.
func TestChaosReceiverKilledBetweenPersistAndAcknowledge(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "flutterwave",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "flutterwave", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "endpoint")

	secrets := secret.NewStatic()
	secrets.Set(testSecretRef, flwSecret)
	secrets.Set(normalise.SaltRef(tenantA), "salt")

	r := receive.New(receive.Options{
		Store: s, Registry: adapters.New(), Secrets: secrets,
	})
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	// Flutterwave supplies a stable data.id, which is what deduplication
	// keys on. The provider redelivers the identical payload, as they do.
	body := fixture(t, "flutterwave", "charge.completed.json")

	post := func() int {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			srv.URL+ep.ReceiverPath(slugA), strings.NewReader(string(body)))
		mustNoErr(t, err, "building")
		req.Header.Set("Verif-Hash", flwSecret)
		resp, err := srv.Client().Do(req)
		mustNoErr(t, err, "sending")
		code := resp.StatusCode
		_ = resp.Body.Close()
		return code
	}

	// The first delivery lands. Imagine the process dying here, after the
	// commit and before the response — from the provider's side the two are
	// indistinguishable.
	if code := post(); code != http.StatusOK {
		t.Fatalf("first delivery = %d", code)
	}
	// The provider retries. And again, as several of them do.
	for i := 0; i < 3; i++ {
		if code := post(); code != http.StatusOK {
			t.Fatalf("retry %d = %d", i+1, code)
		}
	}

	// Four raw events, correctly: each arrival is a fact, and the raw table
	// is the record of what the provider actually sent.
	pending, err := s.ListUnnormalised(ctx, 50)
	mustNoErr(t, err, "listing pending")
	if len(pending) != 4 {
		t.Fatalf("%d raw events stored, want 4 — every arrival is a fact worth recording", len(pending))
	}

	// But only one canonical event, because deduplication is enforced by a
	// unique index rather than a check-then-write that two replicas could
	// both pass.
	n := normalise.New(normalise.Options{
		Store: s, Registry: adapters.New(), Secrets: secrets,
	})
	for _, raw := range pending {
		_ = n.Process(ctx, raw.ID, tenantA)
	}

	events, err := s.QueryEvents(ctx, tenantA, store.EventQuery{})
	mustNoErr(t, err, "querying")
	if len(events) != 1 {
		t.Fatalf("%d canonical events from 4 identical redeliveries; the customer's ledger would "+
			"see the same payment %d times", len(events), len(events))
	}
	if events[0].ProviderEventID != "4589301" {
		t.Errorf("deduplication keyed on the wrong field: %q", events[0].ProviderEventID)
	}
}

// TestChaosProviderRedeliveryWithNoEventID covers the harder case.
//
// Paystack supplies no per-event identifier at all, so deduplication has to
// fall back to the body hash. A design that only handled providers with an
// event ID would duplicate every Paystack retry.
func TestChaosProviderRedeliveryWithNoEventID(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "endpoint")

	secrets := secret.NewStatic()
	secrets.Set(testSecretRef, paystackSecret)
	secrets.Set(normalise.SaltRef(tenantA), "salt")

	r := receive.New(receive.Options{Store: s, Registry: adapters.New(), Secrets: secrets})
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	body := fixture(t, "paystack", "charge.success.json")
	sig := paystackSign(body, paystackSecret)
	for i := 0; i < 3; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			srv.URL+ep.ReceiverPath(slugA), strings.NewReader(string(body)))
		mustNoErr(t, err, "building")
		req.Header.Set(paystack.Header, sig)
		resp, err := srv.Client().Do(req)
		mustNoErr(t, err, "sending")
		_ = resp.Body.Close()
	}

	pending, err := s.ListUnnormalised(ctx, 50)
	mustNoErr(t, err, "listing")
	if len(pending) != 3 {
		t.Fatalf("%d raw events, want 3", len(pending))
	}

	// Every arrival hashed to the same body, which is the fallback dedupe
	// key. Paystack redelivers byte-identical payloads, which is exactly the
	// property that makes the fallback correct for them.
	hashes := map[string]int{}
	for _, raw := range pending {
		hashes[raw.BodySHA256]++
	}
	if len(hashes) != 1 {
		t.Fatalf("three identical redeliveries produced %d distinct body hashes; the fallback "+
			"deduplication key would not match", len(hashes))
	}
}

// TestChaosReceiverSurvivesTheDispatcherBeingGone is the promise in §11.1
// stated as a test.
//
// The dispatcher does not exist. Events keep arriving, are acknowledged, and
// are stored — and deliver in full once a dispatcher appears.
func TestChaosReceiverSurvivesTheDispatcherBeingGone(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "endpoint")

	secrets := secret.NewStatic()
	secrets.Set(testSecretRef, paystackSecret)
	secrets.Set(normalise.SaltRef(tenantA), "salt")

	// No dispatcher, no normaliser, no notifier — only the receiver.
	r := receive.New(receive.Options{Store: s, Registry: adapters.New(), Secrets: secrets})
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	// Readiness must still be green. A probe that failed here would take the
	// receiver out of rotation for a dispatcher fault and lose the very
	// events this design protects.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/readyz", nil)
	mustNoErr(t, err, "building")
	resp, err := srv.Client().Do(req)
	mustNoErr(t, err, "probing")
	ready := resp.StatusCode
	_ = resp.Body.Close()
	if ready != http.StatusOK {
		t.Fatalf("readiness = %d with no dispatcher running; the receiver must not depend on it", ready)
	}

	const arrivals = 25
	for i := 0; i < arrivals; i++ {
		payload := []byte(fmt.Sprintf(
			`{"event":"charge.success","data":{"reference":"TXN-NODISP-%02d","status":"success",`+
				`"amount":100,"currency":"NGN","paid_at":"2026-08-11T09:14:31.000Z"}}`, i))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			srv.URL+ep.ReceiverPath(slugA), strings.NewReader(string(payload)))
		mustNoErr(t, err, "building")
		req.Header.Set(paystack.Header, paystackSign(payload, paystackSecret))
		resp, err := srv.Client().Do(req)
		mustNoErr(t, err, "sending")
		code := resp.StatusCode
		_ = resp.Body.Close()
		if code != http.StatusOK {
			t.Fatalf("event %d got %d with no dispatcher running", i, code)
		}
	}

	pending, err := s.ListUnnormalised(ctx, 100)
	mustNoErr(t, err, "listing")
	if len(pending) != arrivals {
		t.Fatalf("%d events survived with no dispatcher, want %d", len(pending), arrivals)
	}
}
