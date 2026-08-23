package tests

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

func TestBreakerOpensAfterConsecutiveFailures(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	b := dispatch.NewBreaker(dispatch.BreakerOptions{
		Threshold: 3, Cooldown: time.Minute, Now: clock.now,
	})

	for i := 0; i < 2; i++ {
		if state := b.Failed("dst_1", "connection refused"); state != dispatch.BreakerClosed {
			t.Fatalf("after %d failures the breaker is %q; two failures are ordinary", i+1, state)
		}
		if ok, _ := b.Allow("dst_1"); !ok {
			t.Fatal("the breaker refused a delivery before the threshold")
		}
	}

	if state := b.Failed("dst_1", "connection refused"); state != dispatch.BreakerOpen {
		t.Fatalf("state after the threshold = %q, want open", state)
	}
	ok, why := b.Allow("dst_1")
	if ok {
		t.Fatal("an open breaker allowed a delivery")
	}
	// The reason has to be actionable. "Unavailable" is not; "connection
	// refused, next probe in 1m0s" is.
	if why == "" {
		t.Error("the breaker refused without saying why")
	}
}

func TestBreakerProbesOnceAfterCooldown(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	b := dispatch.NewBreaker(dispatch.BreakerOptions{
		Threshold: 1, Cooldown: time.Minute, Now: clock.now,
	})
	b.Failed("dst_1", "down")

	if ok, _ := b.Allow("dst_1"); ok {
		t.Fatal("probed before the cooldown elapsed")
	}
	clock.advance(61 * time.Second)

	// Exactly one probe. Letting several through means a destination that is
	// still down takes a burst on every cooldown, which is the behaviour the
	// breaker exists to prevent.
	if ok, _ := b.Allow("dst_1"); !ok {
		t.Fatal("no probe was allowed after the cooldown")
	}
	if ok, why := b.Allow("dst_1"); ok {
		t.Fatalf("a second concurrent probe was allowed (%s)", why)
	}
}

func TestBreakerBacksOffWhenAProbeFails(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	b := dispatch.NewBreaker(dispatch.BreakerOptions{
		Threshold: 1, Cooldown: time.Minute, MaxCooldown: 8 * time.Minute, Now: clock.now,
	})
	b.Failed("dst_1", "down")

	// Each failed probe doubles the wait, so a destination down for a day is
	// not probed at the same rate forever.
	for _, want := range []time.Duration{2 * time.Minute, 4 * time.Minute, 8 * time.Minute} {
		// Wait out the current cooldown, probe, and fail the probe.
		clock.advance(want)
		if ok, why := b.Allow("dst_1"); !ok {
			t.Fatalf("no probe allowed before the %s step: %s", want, why)
		}
		b.Failed("dst_1", "still down")

		// The next wait is the doubled one, so just short of it is refused.
		clock.advance(want - time.Second)
		if ok, _ := b.Allow("dst_1"); ok {
			t.Fatalf("probed %s early; the cooldown should now be %s", time.Second, want)
		}
		clock.advance(time.Second)
	}

	// And the backoff is capped rather than doubling indefinitely: after
	// another failed probe the wait is still eight minutes, not sixteen.
	if ok, _ := b.Allow("dst_1"); !ok {
		t.Fatal("no probe allowed at the capped cooldown")
	}
	b.Failed("dst_1", "still down")
	snapshot := b.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if snapshot[0].NextProbeIn > 8*time.Minute {
		t.Errorf("cooldown grew past the cap: %s", snapshot[0].NextProbeIn)
	}
}

func TestBreakerClosesOnOneSuccess(t *testing.T) {
	// The half-open probe is a real delivery carrying a real event, so the
	// destination has already shown it can accept one. Holding the breaker
	// open after that delays everything else for no new information.
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	b := dispatch.NewBreaker(dispatch.BreakerOptions{Threshold: 1, Cooldown: time.Minute, Now: clock.now})

	b.Failed("dst_1", "down")
	clock.advance(2 * time.Minute)
	if ok, _ := b.Allow("dst_1"); !ok {
		t.Fatal("no probe allowed")
	}
	b.Succeeded("dst_1")

	if b.State("dst_1") != dispatch.BreakerClosed {
		t.Fatalf("state = %q after a successful probe", b.State("dst_1"))
	}
	for i := 0; i < 5; i++ {
		if ok, _ := b.Allow("dst_1"); !ok {
			t.Fatal("a closed breaker refused a delivery")
		}
	}
}

func TestBreakerIsPerDestination(t *testing.T) {
	// One customer's outage must not stop deliveries to anyone else.
	b := dispatch.NewBreaker(dispatch.BreakerOptions{Threshold: 1})
	b.Failed("dst_broken", "down")

	if ok, _ := b.Allow("dst_broken"); ok {
		t.Error("the broken destination is not tripped")
	}
	if ok, _ := b.Allow("dst_fine"); !ok {
		t.Fatal("a healthy destination was blocked by another's breaker")
	}
}

func TestBreakerResetIsImmediate(t *testing.T) {
	// An operator who has just fixed the destination should not wait out a
	// cooldown that is now measuring nothing.
	b := dispatch.NewBreaker(dispatch.BreakerOptions{Threshold: 1, Cooldown: time.Hour})
	b.Failed("dst_1", "down")
	if ok, _ := b.Allow("dst_1"); ok {
		t.Fatal("not tripped")
	}
	b.Reset("dst_1")
	if ok, _ := b.Allow("dst_1"); !ok {
		t.Fatal("reset did not close the breaker")
	}
}

// TestBreakerParksWithoutSpendingTheRetryBudget is the assertion the whole
// feature exists for.
//
// Without it, a thirty-minute outage silently consumes every queued event's
// retries and dead-letters the lot at the moment the customer's service comes
// back — turning a recoverable outage into a bulk replay.
func TestBreakerParksWithoutSpendingTheRetryBudget(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	// The threshold must be below the retry budget, or the breaker trips only
	// after the event it was meant to protect has already dead-lettered. The
	// shipped defaults hold that relationship — five consecutive failures
	// against a seven-attempt schedule — and this test picks two against
	// three for the same reason at a smaller scale.
	breaker := dispatch.NewBreaker(dispatch.BreakerOptions{
		Threshold: 2, Cooldown: 30 * time.Second, Now: clock.now,
	})
	h := newDispatchHarnessWith(t, domain.RetryPolicy{
		Backoff: []time.Duration{0, time.Second, time.Second},
		Timeout: time.Second,
	}, breaker, clock)
	ctx := context.Background()
	h.sink.setResponder(func(int) (int, string) { return http.StatusServiceUnavailable, "down" })

	ev := h.event(t, "TXN-BREAK", domain.StatusSuccess, h.clock.now())
	mustNoErr(t, h.d.Enqueue(ctx, ev), "enqueuing")

	// Drive enough passes that, without a breaker, the retry budget would be
	// long gone.
	for i := 0; i < 20; i++ {
		h.drain(t, 1)
		h.clock.advance(2 * time.Second)
	}

	dels, err := h.store.ListDeliveriesForEvent(ctx, tenantA, ev.ID)
	mustNoErr(t, err, "listing")
	if len(dels) != 1 {
		t.Fatalf("%d deliveries", len(dels))
	}
	if dels[0].Status == domain.DeliveryDeadLetter {
		t.Fatal("the delivery dead-lettered during an outage: the breaker consumed its retry budget")
	}

	// The breaker is open and the sink has been spared the pile-on: far
	// fewer requests than passes.
	if state := h.d.Breaker().State(h.dest.ID); state == dispatch.BreakerClosed {
		t.Errorf("breaker is %q after sustained failure", state)
	}
	if h.sink.count() > 8 {
		t.Errorf("the failing destination received %d requests across 20 passes; the breaker is not limiting load", h.sink.count())
	}

	// It recovers, and the event is delivered on the next probe.
	h.sink.setResponder(func(int) (int, string) { return http.StatusOK, "" })
	for i := 0; i < 10; i++ {
		h.clock.advance(time.Minute)
		h.drain(t, 2)
	}

	dels, err = h.store.ListDeliveriesForEvent(ctx, tenantA, ev.ID)
	mustNoErr(t, err, "listing after recovery")
	if dels[0].Status != domain.DeliverySucceeded {
		t.Fatalf("after recovery the delivery is %q, want succeeded", dels[0].Status)
	}
}

func TestBreakerIgnoresPayloadRejections(t *testing.T) {
	// A 400 is about this payload, not the destination's health. Counting it
	// would trip the breaker for every other event because one was malformed.
	h := newDispatchHarness(t, domain.RetryPolicy{Backoff: []time.Duration{0}, Timeout: time.Second})
	ctx := context.Background()
	h.sink.setResponder(func(int) (int, string) { return http.StatusBadRequest, "unknown currency" })

	for i := 0; i < 10; i++ {
		ev := h.event(t, domain.NewID("txn"), domain.StatusSuccess, h.clock.now())
		mustNoErr(t, h.d.Enqueue(ctx, ev), "enqueuing")
	}
	h.drain(t, 10)

	if state := h.d.Breaker().State(h.dest.ID); state != dispatch.BreakerClosed {
		t.Fatalf("ten 400s tripped the breaker (%q); they say nothing about the destination's health", state)
	}
}

func TestBreakerSnapshotIsActionable(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	b := dispatch.NewBreaker(dispatch.BreakerOptions{Threshold: 2, Cooldown: time.Minute, Now: clock.now})
	b.Failed("dst_1", "dial tcp: connection refused")
	b.Failed("dst_1", "dial tcp: connection refused")

	snap := b.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
	h := snap[0]
	if h.State != dispatch.BreakerOpen || h.ConsecutiveFailures != 2 {
		t.Errorf("health = %+v", h)
	}
	// "This destination is unavailable" is not actionable. The cause is.
	if h.LastError == "" {
		t.Error("no last error recorded, so the dashboard cannot say why")
	}
	if h.NextProbeIn <= 0 {
		t.Error("no next-probe time, so nobody knows when it will be retried")
	}
	if h.Trips != 1 {
		t.Errorf("trips = %d", h.Trips)
	}
}
