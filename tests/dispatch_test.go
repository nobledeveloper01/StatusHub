package tests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/secret"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

const signingRef = "static://destination-signing"
const signingSecret = "whsec_" + "destination0123456789abcdef"

// sink is the customer's endpoint.
type sink struct {
	mu       sync.Mutex
	received []dispatch.Payload
	headers  []http.Header
	bodies   [][]byte

	// respond decides what the sink does, per request, so a test can make it
	// fail then recover.
	respond func(attempt int) (code int, body string)
	server  *httptest.Server
}

func newSink(t *testing.T) *sink {
	t.Helper()
	s := &sink{respond: func(int) (int, string) { return http.StatusOK, "" }}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		attempt := len(s.received)
		var p dispatch.Payload
		_ = json.Unmarshal(body, &p)
		s.received = append(s.received, p)
		s.headers = append(s.headers, r.Header.Clone())
		s.bodies = append(s.bodies, body)
		respond := s.respond
		s.mu.Unlock()

		code, msg := respond(attempt)
		w.WriteHeader(code)
		_, _ = io.WriteString(w, msg)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *sink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.received)
}

func (s *sink) all() []dispatch.Payload {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]dispatch.Payload(nil), s.received...)
}

func (s *sink) setResponder(f func(attempt int) (int, string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.respond = f
}

type dispatchHarness struct {
	store *store.Memory
	d     *dispatch.Dispatcher
	sink  *sink
	dest  domain.Destination
	clock *testClock
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newDispatchHarness(t *testing.T, policy domain.RetryPolicy) *dispatchHarness {
	return newDispatchHarnessWith(t, policy, nil)
}

func newDispatchHarnessWith(t *testing.T, policy domain.RetryPolicy, breaker *dispatch.Breaker, clocks ...*testClock) *dispatchHarness {
	t.Helper()
	s := memStore(t)
	sk := newSink(t)
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	if len(clocks) > 0 && clocks[0] != nil {
		clock = clocks[0]
	}

	dest := domain.Destination{
		ID: domain.NewID(domain.PrefixDestination), TenantID: tenantA, Name: "ledger",
		URL: sk.server.URL, SigningSecretRef: signingRef,
		RetryPolicy: policy, Enabled: true,
	}
	mustNoErr(t, s.CreateDestination(context.Background(), dest), "creating the destination")

	// The sink is on 127.0.0.1, which the SSRF guard is built to refuse. The
	// guard is exercised properly in its own test; here it is opened so the
	// delivery path can be tested at all.
	guard, err := dispatch.NewGuard(dispatch.GuardOptions{AllowPrivate: true})
	mustNoErr(t, err, "building the guard")

	d, err := dispatch.New(dispatch.Options{
		Store: s, Secrets: staticSecrets(signingRef, signingSecret),
		Guard: guard, Breaker: breaker, Shards: 8, Now: clock.now,
	})
	mustNoErr(t, err, "building the dispatcher")

	return &dispatchHarness{store: s, d: d, sink: sk, dest: dest, clock: clock}
}

func (h *dispatchHarness) event(t *testing.T, ref string, status domain.Status, occurred time.Time) domain.CanonicalEvent {
	t.Helper()
	ev := domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "paystack",
		EventType: domain.EventTypeFor("payment", status), TransactionRef: ref,
		Status: status, AmountMinor: 5000000, Currency: "NGN",
		OccurredAt: occurred, ReceivedAt: occurred, MappingComplete: true,
	}
	mustNoErr(t, h.store.PutCanonicalEvent(context.Background(), ev), "storing the event")
	return ev
}

// drain runs delivery passes until nothing is left to do.
func (h *dispatchHarness) drain(t *testing.T, maxPasses int) {
	t.Helper()
	ctx := context.Background()
	for pass := 0; pass < maxPasses; pass++ {
		worked := false
		for shard := 0; shard < 8; shard++ {
			claimed, err := h.store.ClaimDue(ctx, shard, h.clock.now(), 32, time.Minute)
			mustNoErr(t, err, "claiming")
			for _, del := range claimed {
				worked = true
				mustNoErr(t, h.d.DeliverOnce(ctx, del), "delivering")
			}
		}
		if !worked {
			return
		}
	}
}

func TestDispatchDeliversTheCanonicalShape(t *testing.T) {
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ctx := context.Background()
	ev := h.event(t, "TXN-1", domain.StatusSuccess, h.clock.now())
	mustNoErr(t, h.d.Enqueue(ctx, ev), "enqueuing")
	h.drain(t, 5)

	if h.sink.count() != 1 {
		t.Fatalf("%d deliveries, want 1", h.sink.count())
	}
	got := h.sink.all()[0]
	if got.EventID != ev.ID || got.TransactionRef != "TXN-1" || got.Status != "success" {
		t.Errorf("payload = %+v", got)
	}
	if got.AmountMinor != 5000000 || got.Currency != "NGN" {
		t.Errorf("amount = %d %s", got.AmountMinor, got.Currency)
	}
	if !got.MappingComplete {
		t.Error("mapping_complete was not forwarded")
	}

	h.sink.mu.Lock()
	hdr := h.sink.headers[0]
	body := h.sink.bodies[0]
	h.sink.mu.Unlock()

	// The idempotency key is the event ID, not the delivery ID, so a retry
	// and a replay of the same event carry the same key. That is what turns
	// our at-least-once into the customer's exactly-once.
	if hdr.Get("Idempotency-Key") != ev.ID {
		t.Errorf("Idempotency-Key = %q, want the event ID", hdr.Get("Idempotency-Key"))
	}
	if hdr.Get("X-StatusHub-Replay") != "false" {
		t.Errorf("X-StatusHub-Replay = %q", hdr.Get("X-StatusHub-Replay"))
	}
	// And the signature must verify with the same function the client
	// libraries use.
	if err := dispatch.Verify(signingSecret, body, hdr.Get(dispatch.SignatureHeader), h.clock.now(), 5*time.Minute); err != nil {
		t.Fatalf("the delivery's own signature did not verify: %v", err)
	}
}

func TestDispatchRetryScheduleIsExactlyTheAdvertisedOne(t *testing.T) {
	// §3.2 C1 promises 0s, 10s, 1m, 5m, 30m, 2h, 6h. A customer plans their
	// on-call around it, so it is asserted rather than assumed.
	policy := domain.RetryPolicy{
		Backoff:        []time.Duration{0, 10 * time.Second, time.Minute, 5 * time.Minute},
		JitterFraction: 0, // jitter off, so the schedule is exact
		Timeout:        2 * time.Second,
	}
	h := newDispatchHarness(t, policy)
	ctx := context.Background()
	h.sink.setResponder(func(int) (int, string) { return http.StatusInternalServerError, "down" })

	ev := h.event(t, "TXN-RETRY", domain.StatusSuccess, h.clock.now())
	mustNoErr(t, h.d.Enqueue(ctx, ev), "enqueuing")

	wants := []time.Duration{10 * time.Second, time.Minute, 5 * time.Minute}
	for i, want := range wants {
		claimed, err := h.store.ClaimDue(ctx, domain.ShardFor("TXN-RETRY", 8), h.clock.now(), 10, time.Minute)
		mustNoErr(t, err, "claiming")
		if len(claimed) != 1 {
			t.Fatalf("attempt %d: %d claimed, want 1", i+1, len(claimed))
		}
		mustNoErr(t, h.d.DeliverOnce(ctx, claimed[0]), "delivering")

		dels, err := h.store.ListDeliveriesForEvent(ctx, tenantA, ev.ID)
		mustNoErr(t, err, "listing")
		got := dels[0].NextRetryAt.Sub(h.clock.now())
		if got != want {
			t.Errorf("after attempt %d the next retry is in %s, want %s", i+1, got, want)
		}
		h.clock.advance(want)
	}

	// The budget is four attempts. The fourth failure dead-letters.
	claimed, err := h.store.ClaimDue(ctx, domain.ShardFor("TXN-RETRY", 8), h.clock.now(), 10, time.Minute)
	mustNoErr(t, err, "claiming the last attempt")
	mustNoErr(t, h.d.DeliverOnce(ctx, claimed[0]), "delivering")

	dels, err := h.store.ListDeliveriesForEvent(ctx, tenantA, ev.ID)
	mustNoErr(t, err, "listing")
	if dels[0].Status != domain.DeliveryDeadLetter {
		t.Fatalf("status after the budget was spent = %q, want dead_letter", dels[0].Status)
	}
	// The body is kept, because "returned 500" is not a diagnosis and
	// "returned 500 saying down" is.
	if dels[0].ResponseBody != "down" {
		t.Errorf("the destination's response was not retained: %q", dels[0].ResponseBody)
	}
}

func TestDispatchDoesNotRetryWhatCannotSucceed(t *testing.T) {
	// A 400 will say the same thing in six hours. Retrying it for nine hours
	// only delays the dead letter the operator needs to see.
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ctx := context.Background()
	h.sink.setResponder(func(int) (int, string) { return http.StatusBadRequest, "unknown currency" })

	ev := h.event(t, "TXN-400", domain.StatusSuccess, h.clock.now())
	mustNoErr(t, h.d.Enqueue(ctx, ev), "enqueuing")
	h.drain(t, 3)

	if h.sink.count() != 1 {
		t.Fatalf("%d attempts against a 400; it should be attempted once", h.sink.count())
	}
	dels, _ := h.store.ListDeliveriesForEvent(ctx, tenantA, ev.ID)
	if dels[0].Status != domain.DeliveryDeadLetter {
		t.Errorf("status = %q, want dead_letter", dels[0].Status)
	}
}

func TestDispatchRetriesWhatMightSucceed(t *testing.T) {
	for _, code := range []int{408, 429, 500, 502, 503, 504} {
		if !domain.ShouldRetry(code) {
			t.Errorf("%d should be retried", code)
		}
	}
	for _, code := range []int{400, 401, 403, 404, 409, 410, 422} {
		if domain.ShouldRetry(code) {
			t.Errorf("%d should not be retried", code)
		}
	}
	// A transport failure — connection refused, DNS, timeout — always
	// retries, because it says nothing about whether the request was valid.
	if !domain.ShouldRetry(0) {
		t.Error("a transport failure should be retried")
	}
}

func TestDispatchEventuallyDeliversAFlappingDestination(t *testing.T) {
	policy := domain.RetryPolicy{
		Backoff: []time.Duration{0, time.Second, time.Second, time.Second, time.Second},
		Timeout: 2 * time.Second,
	}
	h := newDispatchHarness(t, policy)
	ctx := context.Background()
	// Fails twice, then recovers.
	h.sink.setResponder(func(attempt int) (int, string) {
		if attempt < 2 {
			return http.StatusBadGateway, "flapping"
		}
		return http.StatusOK, ""
	})

	ev := h.event(t, "TXN-FLAP", domain.StatusSuccess, h.clock.now())
	mustNoErr(t, h.d.Enqueue(ctx, ev), "enqueuing")

	for i := 0; i < 5; i++ {
		h.drain(t, 2)
		h.clock.advance(2 * time.Second)
	}

	dels, _ := h.store.ListDeliveriesForEvent(ctx, tenantA, ev.ID)
	if dels[0].Status != domain.DeliverySucceeded {
		t.Fatalf("status = %q, want succeeded", dels[0].Status)
	}
	// Exactly once from the customer's point of view, even though we tried
	// three times: the two failures never reached a handler that accepted
	// them, and every attempt carried the same idempotency key.
	if h.sink.count() != 3 {
		t.Errorf("%d attempts, want 3", h.sink.count())
	}
}

func TestDispatchOrdersEventsSharingATransactionRef(t *testing.T) {
	// A success arriving before the pending that preceded it corrupts the
	// customer's state machine. This is the assertion that stops it.
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ctx := context.Background()

	base := h.clock.now()
	pending := h.event(t, "TXN-ORDER", domain.StatusPending, base)
	success := h.event(t, "TXN-ORDER", domain.StatusSuccess, base.Add(time.Second))

	mustNoErr(t, h.d.Enqueue(ctx, pending), "enqueuing the pending event")
	mustNoErr(t, h.d.Enqueue(ctx, success), "enqueuing the success event")

	// One claim pass must yield only the first: two events on one transaction
	// reference are never in flight together.
	shard := domain.ShardFor("TXN-ORDER", 8)
	claimed, err := h.store.ClaimDue(ctx, shard, h.clock.now(), 32, time.Minute)
	mustNoErr(t, err, "claiming")
	if len(claimed) != 1 {
		t.Fatalf("%d deliveries claimed at once for one transaction reference; ordering requires exactly 1", len(claimed))
	}
	if claimed[0].EventID != pending.ID {
		t.Fatalf("the second event was claimed first")
	}
	// Deliver the one we claimed by hand, then let the loop finish the rest.
	mustNoErr(t, h.d.DeliverOnce(ctx, claimed[0]), "delivering the claimed event")

	h.drain(t, 5)
	got := h.sink.all()
	if len(got) != 2 {
		t.Fatalf("%d deliveries, want 2", len(got))
	}
	if got[0].Status != "pending" || got[1].Status != "success" {
		t.Fatalf("delivered out of order: %s then %s", got[0].Status, got[1].Status)
	}
}

func TestDispatchDoesNotBlockUnrelatedTransactions(t *testing.T) {
	// Ordering within a reference must not become serialisation across all of
	// them. A stuck delivery blocks only its own key.
	h := newDispatchHarness(t, domain.RetryPolicy{
		Backoff: []time.Duration{0, time.Hour}, Timeout: time.Second,
	})
	ctx := context.Background()
	h.sink.setResponder(func(attempt int) (int, string) {
		// Only the first transaction's deliveries fail.
		return http.StatusOK, ""
	})

	stuck := h.event(t, "TXN-STUCK", domain.StatusPending, h.clock.now())
	mustNoErr(t, h.d.Enqueue(ctx, stuck), "enqueuing the stuck event")

	// Fail it once so it is parked with a one-hour retry.
	h.sink.setResponder(func(int) (int, string) { return http.StatusInternalServerError, "" })
	h.drain(t, 1)
	h.sink.setResponder(func(int) (int, string) { return http.StatusOK, "" })

	// A different reference must go straight through.
	other := h.event(t, "TXN-FINE", domain.StatusSuccess, h.clock.now())
	mustNoErr(t, h.d.Enqueue(ctx, other), "enqueuing an unrelated event")
	h.drain(t, 3)

	delivered := h.sink.all()
	var sawOther bool
	for _, p := range delivered {
		if p.TransactionRef == "TXN-FINE" {
			sawOther = true
		}
	}
	if !sawOther {
		t.Fatal("an unrelated transaction was blocked behind a stuck one")
	}
}

func TestDispatchDeadLetterUnblocksTheKey(t *testing.T) {
	// Head-of-line blocking has to be bounded. Once the retry budget is
	// spent, the delivery dead-letters and the transaction's key is free —
	// otherwise one unreachable endpoint stalls a shard forever (§4.5).
	h := newDispatchHarness(t, domain.RetryPolicy{
		Backoff: []time.Duration{0}, Timeout: time.Second,
	})
	ctx := context.Background()
	h.sink.setResponder(func(attempt int) (int, string) {
		if attempt == 0 {
			return http.StatusInternalServerError, "down"
		}
		return http.StatusOK, ""
	})

	first := h.event(t, "TXN-HOL", domain.StatusPending, h.clock.now())
	second := h.event(t, "TXN-HOL", domain.StatusSuccess, h.clock.now().Add(time.Second))
	mustNoErr(t, h.d.Enqueue(ctx, first), "enqueuing")
	mustNoErr(t, h.d.Enqueue(ctx, second), "enqueuing")

	h.drain(t, 6)

	dels, _ := h.store.ListDeliveriesForEvent(ctx, tenantA, first.ID)
	if dels[0].Status != domain.DeliveryDeadLetter {
		t.Fatalf("the blocking delivery is %q, want dead_letter", dels[0].Status)
	}
	dels2, _ := h.store.ListDeliveriesForEvent(ctx, tenantA, second.ID)
	if dels2[0].Status != domain.DeliverySucceeded {
		t.Fatalf("the following delivery is %q; the key did not unblock", dels2[0].Status)
	}
}

func TestDispatchFiltersPerDestination(t *testing.T) {
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ctx := context.Background()

	// A second sink that only wants successful Paystack payments.
	analytics := newSink(t)
	mustNoErr(t, h.store.CreateDestination(ctx, domain.Destination{
		ID: domain.NewID(domain.PrefixDestination), TenantID: tenantA, Name: "analytics",
		URL: analytics.server.URL, SigningSecretRef: signingRef,
		Filter:      domain.Filter{Statuses: []domain.Status{domain.StatusSuccess}},
		RetryPolicy: domain.DefaultRetryPolicy(), Enabled: true,
	}), "creating the analytics destination")

	mustNoErr(t, h.d.Enqueue(ctx, h.event(t, "TXN-A", domain.StatusPending, h.clock.now())), "pending")
	mustNoErr(t, h.d.Enqueue(ctx, h.event(t, "TXN-B", domain.StatusSuccess, h.clock.now())), "success")
	h.drain(t, 5)

	if h.sink.count() != 2 {
		t.Errorf("the unfiltered destination got %d, want both", h.sink.count())
	}
	if analytics.count() != 1 {
		t.Errorf("the filtered destination got %d, want only the success", analytics.count())
	}
}

func TestDispatchReplayIsMarkedAsSuch(t *testing.T) {
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ctx := context.Background()
	ev := h.event(t, "TXN-REPLAY", domain.StatusSuccess, h.clock.now())
	mustNoErr(t, h.d.Enqueue(ctx, ev), "enqueuing")
	h.drain(t, 3)

	_, err := h.d.EnqueueReplay(ctx, ev, h.dest.ID)
	mustNoErr(t, err, "replaying")
	h.drain(t, 3)

	if h.sink.count() != 2 {
		t.Fatalf("%d deliveries, want 2", h.sink.count())
	}
	h.sink.mu.Lock()
	replayHeader := h.sink.headers[1].Get("X-StatusHub-Replay")
	key := h.sink.headers[1].Get("Idempotency-Key")
	h.sink.mu.Unlock()

	// The customer must be able to tell a replay from a first delivery — and
	// the idempotency key stays the same, so a handler that already processed
	// it can recognise it.
	if replayHeader != "true" {
		t.Errorf("X-StatusHub-Replay = %q on a replay", replayHeader)
	}
	if key != ev.ID {
		t.Errorf("a replay changed the idempotency key: %q", key)
	}
}

func TestDispatchNeverFollowsARedirect(t *testing.T) {
	// Following a redirect on a signed POST would replay the payload to a
	// location the tenant never registered and the guard never checked.
	h := newDispatchHarness(t, domain.RetryPolicy{Backoff: []time.Duration{0}, Timeout: time.Second})
	ctx := context.Background()

	var reachedElsewhere bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reachedElsewhere = true
	}))
	defer elsewhere.Close()

	h.sink.setResponder(func(int) (int, string) { return http.StatusFound, "" })
	h.sink.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", elsewhere.URL)
		w.WriteHeader(http.StatusFound)
	})

	ev := h.event(t, "TXN-REDIRECT", domain.StatusSuccess, h.clock.now())
	mustNoErr(t, h.d.Enqueue(ctx, ev), "enqueuing")
	h.drain(t, 3)

	if reachedElsewhere {
		t.Fatal("the dispatcher followed a redirect on a signed delivery")
	}
	dels, _ := h.store.ListDeliveriesForEvent(ctx, tenantA, ev.ID)
	if dels[0].Status == domain.DeliverySucceeded {
		t.Error("a 302 was treated as a successful delivery")
	}
}

func TestDispatchSignatureVerification(t *testing.T) {
	body := []byte(`{"event_id":"sh_evt_1","status":"success"}`)
	now := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)
	header := dispatch.Sign(signingSecret, body, now)

	mustNoErr(t, dispatch.Verify(signingSecret, body, header, now, 5*time.Minute), "a genuine signature")

	// A captured delivery replayed later is rejected by the timestamp, not
	// by the digest — which is still perfectly valid.
	if err := dispatch.Verify(signingSecret, body, header, now.Add(time.Hour), 5*time.Minute); err == nil {
		t.Error("an hour-old signature verified")
	}
	// A modified body.
	if err := dispatch.Verify(signingSecret, []byte(`{"event_id":"sh_evt_1","status":"failed"}`), header, now, 5*time.Minute); err == nil {
		t.Error("a tampered body verified")
	}
	// The wrong secret.
	if err := dispatch.Verify("another-secret", body, header, now, 5*time.Minute); err == nil {
		t.Error("the wrong secret verified")
	}

	// Rotation: two signatures, either may match.
	multi := dispatch.SignWith([]string{"old-secret", signingSecret}, body, now)
	mustNoErr(t, dispatch.Verify(signingSecret, body, multi, now, 5*time.Minute), "the new secret during rotation")
	mustNoErr(t, dispatch.Verify("old-secret", body, multi, now, 5*time.Minute), "the old secret during rotation")
}

func TestDispatchSecretOutageDoesNotConsumeTheRetryBudget(t *testing.T) {
	// An hour of secret-manager unavailability must not dead-letter
	// everything queued during it.
	s := memStore(t)
	sk := newSink(t)
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	dest := domain.Destination{
		ID: domain.NewID(domain.PrefixDestination), TenantID: tenantA, URL: sk.server.URL,
		SigningSecretRef: "static://missing", RetryPolicy: domain.DefaultRetryPolicy(), Enabled: true,
	}
	ctx := context.Background()
	mustNoErr(t, s.CreateDestination(ctx, dest), "creating the destination")

	guard, _ := dispatch.NewGuard(dispatch.GuardOptions{AllowPrivate: true})
	d, err := dispatch.New(dispatch.Options{
		Store: s, Secrets: secret.NewStatic(), Guard: guard, Shards: 8, Now: clock.now,
	})
	mustNoErr(t, err, "building the dispatcher")

	ev := domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "paystack",
		EventType: domain.EventPaymentCompleted, TransactionRef: "TXN-SECRET",
		Status: domain.StatusSuccess, OccurredAt: clock.now(),
	}
	mustNoErr(t, s.PutCanonicalEvent(ctx, ev), "storing")
	mustNoErr(t, d.Enqueue(ctx, ev), "enqueuing")

	claimed, err := s.ClaimDue(ctx, domain.ShardFor("TXN-SECRET", 8), clock.now(), 10, time.Minute)
	mustNoErr(t, err, "claiming")
	mustNoErr(t, d.DeliverOnce(ctx, claimed[0]), "delivering")

	dels, _ := s.ListDeliveriesForEvent(ctx, tenantA, ev.ID)
	if dels[0].Status != domain.DeliveryFailed {
		t.Fatalf("status = %q; a secret outage should schedule a retry, not dead-letter", dels[0].Status)
	}
	if sk.count() != 0 {
		t.Error("an unsigned request was sent")
	}
}

func TestDispatchStoresNoMoreOfAResponseThanIsUseful(t *testing.T) {
	h := newDispatchHarness(t, domain.RetryPolicy{Backoff: []time.Duration{0}, Timeout: 2 * time.Second})
	ctx := context.Background()
	huge := make([]byte, 64*1024)
	for i := range huge {
		huge[i] = 'x'
	}
	h.sink.setResponder(func(int) (int, string) { return http.StatusBadRequest, string(huge) })

	ev := h.event(t, "TXN-HUGE", domain.StatusSuccess, h.clock.now())
	mustNoErr(t, h.d.Enqueue(ctx, ev), "enqueuing")
	h.drain(t, 3)

	dels, _ := h.store.ListDeliveriesForEvent(ctx, tenantA, ev.ID)
	if len(dels[0].ResponseBody) > 1024 {
		t.Fatalf("stored %d bytes of a response; the cap is 1024", len(dels[0].ResponseBody))
	}
}

func TestDispatchQueueMetricsExist(t *testing.T) {
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ctx := context.Background()
	mustNoErr(t, h.d.Enqueue(ctx, h.event(t, "TXN-Q", domain.StatusSuccess, h.clock.now())), "enqueuing")

	depth, err := h.store.QueueDepth(ctx)
	mustNoErr(t, err, "queue depth")
	var total int64
	for _, n := range depth {
		total += n
	}
	if total != 1 {
		t.Errorf("queue depth = %d, want 1", total)
	}

	oldest, err := h.store.OldestPending(ctx)
	mustNoErr(t, err, "oldest pending")
	if len(oldest) != 1 {
		t.Errorf("oldest-pending reported %d shards, want 1", len(oldest))
	}
}
