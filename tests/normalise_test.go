package tests

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapters"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/normalise"
	"github.com/nobledeveloper01/StatusHub/internal/secret"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

type capturingEnqueuer struct {
	mu     sync.Mutex
	events []domain.CanonicalEvent
}

func (c *capturingEnqueuer) Enqueue(_ context.Context, e domain.CanonicalEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}

func (c *capturingEnqueuer) all() []domain.CanonicalEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]domain.CanonicalEvent(nil), c.events...)
}

type normaliseHarness struct {
	store    *store.Memory
	n        *normalise.Normaliser
	enqueued *capturingEnqueuer
	endpoint domain.Endpoint
}

func newNormaliseHarness(t *testing.T, provider, adapterName string) *normaliseHarness {
	t.Helper()
	s := memStore(t)
	ctx := context.Background()

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: provider,
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: adapterName, Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "creating the endpoint")

	secrets := secret.NewStatic()
	secrets.Set(testSecretRef, paystackSecret)
	secrets.Set(normalise.SaltRef(tenantA), "a-per-tenant-salt")
	secrets.Set(normalise.SaltRef(tenantB), "a-different-tenant-salt")

	enq := &capturingEnqueuer{}
	return &normaliseHarness{
		store:    s,
		enqueued: enq,
		endpoint: ep,
		n: normalise.New(normalise.Options{
			Store: s, Registry: adapters.New(), Secrets: secrets, Enqueuer: enq,
		}),
	}
}

func (h *normaliseHarness) receive(t *testing.T, body []byte, valid bool) domain.RawEvent {
	t.Helper()
	raw := domain.RawEvent{
		ID: domain.NewID(domain.PrefixRawEvent), TenantID: tenantA, EndpointID: h.endpoint.ID,
		Provider: h.endpoint.Provider, Body: body, BodySHA256: "hash-" + string(body[:8]),
		SignatureValid: valid, ReceivedAt: time.Now().UTC(),
	}
	mustNoErr(t, h.store.PutRawEvent(context.Background(), raw), "storing the raw event")
	return raw
}

func TestNormaliseProducesOneShapeFromEveryProvider(t *testing.T) {
	// The product in one test: six providers, six wildly different payloads,
	// one schema out the other side.
	cases := []struct {
		provider   string
		file       string
		wantRef    string
		wantMinor  int64
		wantStatus domain.Status
	}{
		{"paystack", "charge.success.json", "TXN-2026-08-11-8842", 5000000, domain.StatusSuccess},
		{"flutterwave", "charge.completed.json", "TXN-2026-08-11-8842", 813455, domain.StatusSuccess},
		{"nibss", "credit.success.json", "TXN-2026-08-11-8842", 5000000, domain.StatusSuccess},
		{"monnify", "transaction.completed.json", "TXN-2026-08-11-8842", 5000000, domain.StatusSuccess},
		{"interswitch", "payment.success.json", "TXN-2026-08-11-8842", 5000000, domain.StatusSuccess},
		{"stripe", "payment_intent.succeeded.json", "TXN-2026-08-11-8842", 5000000, domain.StatusSuccess},
	}

	for _, c := range cases {
		t.Run(c.provider, func(t *testing.T) {
			h := newNormaliseHarness(t, c.provider, c.provider)
			raw := h.receive(t, fixture(t, c.provider, c.file), true)
			mustNoErr(t, h.n.Process(context.Background(), raw.ID, tenantA), "normalising")

			enqueued := h.enqueued.all()
			if len(enqueued) != 1 {
				t.Fatalf("%d events queued, want 1", len(enqueued))
			}
			ev := enqueued[0]

			// Every one of these is the same assertion made six times, which
			// is the point: the customer's handler sees this shape whichever
			// provider sent the event.
			if ev.TransactionRef != c.wantRef {
				t.Errorf("transaction_ref = %q, want %q", ev.TransactionRef, c.wantRef)
			}
			if ev.AmountMinor != c.wantMinor {
				t.Errorf("amount_minor = %d, want %d", ev.AmountMinor, c.wantMinor)
			}
			if ev.Currency != "NGN" {
				t.Errorf("currency = %q, want NGN", ev.Currency)
			}
			if ev.Status != c.wantStatus {
				t.Errorf("status = %q, want %q", ev.Status, c.wantStatus)
			}
			if ev.OccurredAt.Location() != time.UTC {
				t.Errorf("occurred_at is %s, must be UTC", ev.OccurredAt.Location())
			}
			if ev.Provider != c.provider {
				t.Errorf("provider = %q", ev.Provider)
			}
			if !domain.HasPrefix(ev.ID, domain.PrefixEvent) {
				t.Errorf("event ID %q does not carry the sh_evt prefix", ev.ID)
			}
		})
	}
}

func TestNormaliseHashesCustomerIdentifiersPerTenant(t *testing.T) {
	h := newNormaliseHarness(t, "paystack", "paystack")
	raw := h.receive(t, fixture(t, "paystack", "charge.success.json"), true)
	mustNoErr(t, h.n.Process(context.Background(), raw.ID, tenantA), "normalising")

	ev := h.enqueued.all()[0]
	if ev.CustomerRefHash == "" {
		t.Fatal("no customer reference was recorded at all")
	}
	// The email must not survive anywhere in the canonical event, in any
	// form. Storing it would make StatusHub a holder of personal data it has
	// no reason to hold (§8.4).
	if strings.Contains(ev.CustomerRefHash, "tunde@example.com") {
		t.Fatalf("the customer email was stored in the clear: %q", ev.CustomerRefHash)
	}
	if !strings.HasPrefix(ev.CustomerRefHash, "sha256:") {
		t.Errorf("customer_ref_hash = %q, want a sha256: prefix", ev.CustomerRefHash)
	}

	// The same person, under a different tenant, must not produce the same
	// hash — otherwise one tenant's leaked data correlates a person across
	// every other tenant.
	other := newNormaliseHarness(t, "paystack", "paystack")
	ctx := context.Background()
	otherEP := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantB, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}

	rawB := domain.RawEvent{
		ID: domain.NewID(domain.PrefixRawEvent), TenantID: tenantB, EndpointID: otherEP.ID,
		Provider: "paystack", Body: fixture(t, "paystack", "charge.success.json"),
		BodySHA256: "hash-b", SignatureValid: true, ReceivedAt: time.Now().UTC(),
	}
	mustNoErr(t, other.store.CreateEndpoint(ctx, otherEP), "endpoint for B")
	mustNoErr(t, other.store.PutRawEvent(ctx, rawB), "raw event for B")
	mustNoErr(t, other.n.Process(ctx, rawB.ID, tenantB), "normalising for B")

	if got := other.enqueued.all()[0].CustomerRefHash; got == ev.CustomerRefHash {
		t.Fatal("the same customer hashed identically under two tenants — the salt is not per tenant")
	}
}

func TestNormaliseNeverTouchesAForgery(t *testing.T) {
	h := newNormaliseHarness(t, "paystack", "paystack")
	raw := h.receive(t, fixture(t, "paystack", "charge.success.json"), false)

	err := h.n.Process(context.Background(), raw.ID, tenantA)
	if !errors.Is(err, normalise.ErrNotNormalisable) {
		t.Fatalf("a forgery was normalised, or failed for the wrong reason: %v", err)
	}
	if n := len(h.enqueued.all()); n != 0 {
		t.Fatalf("%d events queued from an unverified payload", n)
	}
}

func TestNormaliseKeepsTheRawEventWhenAnAdapterFails(t *testing.T) {
	// This is the whole argument for persist-then-acknowledge. The provider
	// changed their payload, our adapter cannot read it, and nothing is lost.
	h := newNormaliseHarness(t, "paystack", "paystack")
	raw := h.receive(t, []byte(`{"event":"charge.success","data":{"status":"success"}}`), true)

	err := h.n.Process(context.Background(), raw.ID, tenantA)
	if !errors.Is(err, normalise.ErrNotNormalisable) {
		t.Fatalf("expected a permanent normalisation failure, got %v", err)
	}

	ctx := context.Background()
	stored, gerr := h.store.GetRawEvent(ctx, tenantA, raw.ID)
	mustNoErr(t, gerr, "the raw event should still be there")
	if string(stored.Body) != `{"event":"charge.success","data":{"status":"success"}}` {
		t.Error("the raw bytes were altered by a failed normalisation")
	}

	// And it stops being handed out as pending work, so the sweep does not
	// spin on it forever.
	pending, perr := h.store.ListUnnormalised(ctx, 10)
	mustNoErr(t, perr, "listing pending")
	if len(pending) != 0 {
		t.Errorf("a permanently failed event is still queued as pending work: %d", len(pending))
	}
}

func TestNormaliseSurfacesUnknownStatusesForMapping(t *testing.T) {
	h := newNormaliseHarness(t, "paystack", "paystack")
	ctx := context.Background()
	raw := h.receive(t, fixture(t, "paystack", "charge.unmapped_status.json"), true)
	mustNoErr(t, h.n.Process(ctx, raw.ID, tenantA), "normalising")

	// The value the product tells you to go and map.
	unknown, err := h.store.UnknownStatuses(ctx, tenantA, time.Time{})
	mustNoErr(t, err, "listing unknown statuses")
	if len(unknown) != 1 {
		t.Fatalf("%d unknown statuses recorded, want 1", len(unknown))
	}
	if unknown[0].RawValue != "part_settled" || unknown[0].Provider != "paystack" {
		t.Errorf("unknown status = %+v", unknown[0])
	}
	if unknown[0].SampleEvent == "" {
		t.Error("no sample event was recorded, so an engineer cannot see the payload")
	}

	// The event is still delivered. Refusing to forward something we cannot
	// classify would be worse than forwarding it honestly labelled.
	ev := h.enqueued.all()[0]
	if ev.Status != domain.StatusUnknown || ev.MappingComplete {
		t.Errorf("event = status %q, mapping_complete %v", ev.Status, ev.MappingComplete)
	}
}

func TestNormaliseIsSafeToRunTwice(t *testing.T) {
	// A crash between writing the canonical event and marking the raw one
	// done is ordinary, not exotic. The second run must not create a second
	// event.
	h := newNormaliseHarness(t, "flutterwave", "flutterwave")
	ctx := context.Background()
	raw := h.receive(t, fixture(t, "flutterwave", "charge.completed.json"), true)

	mustNoErr(t, h.n.Process(ctx, raw.ID, tenantA), "first pass")
	mustNoErr(t, h.n.Process(ctx, raw.ID, tenantA), "second pass should be a no-op, not an error")

	events, err := h.store.QueryEvents(ctx, tenantA, store.EventQuery{})
	mustNoErr(t, err, "querying")
	if len(events) != 1 {
		t.Fatalf("%d canonical events after two passes, want 1", len(events))
	}
}

func TestNormaliseWorkerRecoversWithoutANotification(t *testing.T) {
	// A notification is an in-memory signal a restart loses. A design where
	// that means a lost event loses events on every deploy, so the sweep is
	// the thing that actually guarantees delivery.
	h := newNormaliseHarness(t, "paystack", "paystack")
	raw := h.receive(t, fixture(t, "paystack", "charge.success.json"), true)

	w := normalise.NewWorker(normalise.WorkerOptions{
		Normaliser: h.n,
		Interval:   20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if events := h.enqueued.all(); len(events) == 1 && events[0].RawEventID == raw.ID {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the sweep never picked up an event that arrived with no notification")
}
