package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

func TestReplayByEventID(t *testing.T) {
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ctx := context.Background()
	ev := h.event(t, "TXN-R1", domain.StatusSuccess, h.clock.now())
	mustNoErr(t, h.d.Enqueue(ctx, ev), "enqueuing")
	h.drain(t, 3)

	res, err := h.d.Replay(ctx, tenantA, dispatch.ReplayRequest{EventIDs: []string{ev.ID}})
	mustNoErr(t, err, "replaying")
	if res.Matched != 1 || res.Queued != 1 {
		t.Fatalf("result = %+v", res)
	}
	h.drain(t, 3)
	if h.sink.count() != 2 {
		t.Fatalf("%d deliveries after a replay, want 2", h.sink.count())
	}
}

func TestReplayDryRunQueuesNothing(t *testing.T) {
	// The first thing anyone should do with a bulk replay is find out how big
	// it is.
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		h.event(t, "TXN-DRY", domain.StatusSuccess, h.clock.now())
	}

	res, err := h.d.Replay(ctx, tenantA, dispatch.ReplayRequest{
		Filter: &store.EventQuery{}, DryRun: true,
	})
	mustNoErr(t, err, "dry run")
	if res.Matched != 5 {
		t.Errorf("matched = %d, want 5", res.Matched)
	}
	if res.Queued != 0 {
		t.Fatalf("a dry run queued %d deliveries", res.Queued)
	}
	if h.sink.count() != 0 {
		t.Fatalf("a dry run sent %d requests", h.sink.count())
	}
}

func TestReplayIsSentAsAReplay(t *testing.T) {
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ctx := context.Background()
	ev := h.event(t, "TXN-R2", domain.StatusSuccess, h.clock.now())

	_, err := h.d.Replay(ctx, tenantA, dispatch.ReplayRequest{EventIDs: []string{ev.ID}})
	mustNoErr(t, err, "replaying")
	h.drain(t, 3)

	h.sink.mu.Lock()
	defer h.sink.mu.Unlock()
	if got := h.sink.headers[0].Get("X-StatusHub-Replay"); got != "true" {
		t.Fatalf("X-StatusHub-Replay = %q; the customer must be able to tell", got)
	}
}

func TestReplayRespectsDestinationFilters(t *testing.T) {
	// A replay that ignored filters would send an analytics sink the pending
	// events it deliberately excluded — a surprise nobody wants mid-recovery.
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ctx := context.Background()

	analytics := newSink(t)
	mustNoErr(t, h.store.CreateDestination(ctx, domain.Destination{
		ID: domain.NewID(domain.PrefixDestination), TenantID: tenantA, Name: "analytics",
		URL: analytics.server.URL, SigningSecretRef: signingRef,
		Filter:      domain.Filter{Statuses: []domain.Status{domain.StatusSuccess}},
		RetryPolicy: domain.DefaultRetryPolicy(), Enabled: true,
	}), "creating the filtered destination")

	pending := h.event(t, "TXN-R3", domain.StatusPending, h.clock.now())
	_, err := h.d.Replay(ctx, tenantA, dispatch.ReplayRequest{EventIDs: []string{pending.ID}})
	mustNoErr(t, err, "replaying")
	h.drain(t, 3)

	if h.sink.count() != 1 {
		t.Errorf("the unfiltered destination got %d, want 1", h.sink.count())
	}
	if analytics.count() != 0 {
		t.Errorf("the filtered destination received %d replayed events it had excluded", analytics.count())
	}
}

func TestReplayNamesTheEventItCouldNotFind(t *testing.T) {
	// An operator pasting a list of IDs should learn which one was wrong.
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ctx := context.Background()
	ev := h.event(t, "TXN-R4", domain.StatusSuccess, h.clock.now())

	_, err := h.d.Replay(ctx, tenantA, dispatch.ReplayRequest{
		EventIDs: []string{ev.ID, "sh_evt_doesnotexist"},
	})
	if err == nil {
		t.Fatal("a replay naming a missing event succeeded")
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("error = %v, want a not-found", err)
	}
	if h.sink.count() != 0 {
		t.Error("a partly-invalid replay queued some deliveries anyway")
	}
}

func TestReplayRefusesToMixIDsAndFilters(t *testing.T) {
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ev := h.event(t, "TXN-R5", domain.StatusSuccess, h.clock.now())
	_, err := h.d.Replay(context.Background(), tenantA, dispatch.ReplayRequest{
		EventIDs: []string{ev.ID}, Filter: &store.EventQuery{},
	})
	mustErr(t, err, "mixing event IDs and a filter")
}

func TestRetryDeadLetterKeepsTheEvidence(t *testing.T) {
	h := newDispatchHarness(t, domain.RetryPolicy{Backoff: []time.Duration{0}, Timeout: time.Second})
	ctx := context.Background()
	h.sink.setResponder(func(attempt int) (int, string) {
		if attempt == 0 {
			return 500, "was down"
		}
		return 200, ""
	})

	ev := h.event(t, "TXN-DLQ", domain.StatusSuccess, h.clock.now())
	mustNoErr(t, h.d.Enqueue(ctx, ev), "enqueuing")
	h.drain(t, 3)

	dead, err := h.store.QueryDeliveries(ctx, tenantA, store.DeliveryQuery{Status: domain.DeliveryDeadLetter})
	mustNoErr(t, err, "listing dead letters")
	if len(dead) != 1 {
		t.Fatalf("%d dead letters, want 1", len(dead))
	}

	newID, err := h.d.RetryDeadLetter(ctx, tenantA, dead[0].ID)
	mustNoErr(t, err, "retrying the dead letter")
	if newID == dead[0].ID {
		t.Fatal("the dead letter was reset in place; it is evidence and must be preserved")
	}
	h.drain(t, 3)

	// The original record still says what happened.
	original, err := h.store.GetDelivery(ctx, tenantA, dead[0].ID)
	mustNoErr(t, err, "fetching the original")
	if original.Status != domain.DeliveryDeadLetter || original.ResponseBody != "was down" {
		t.Errorf("the original dead letter was altered: %+v", original)
	}
	retried, err := h.store.GetDelivery(ctx, tenantA, newID)
	mustNoErr(t, err, "fetching the retry")
	if retried.Status != domain.DeliverySucceeded {
		t.Errorf("the retry is %q", retried.Status)
	}
}

func TestSweepFindsEventsThatWereNeverQueued(t *testing.T) {
	// A crash between storing an event and queueing its delivery leaves an
	// event that is stored, searchable, and silently never forwarded — the
	// worst combination, because it looks fine everywhere an operator would
	// think to look.
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ctx := context.Background()
	h.event(t, "TXN-ORPHAN", domain.StatusSuccess, h.clock.now())

	queued, err := h.d.SweepUndelivered(ctx, tenantA, time.Time{}, 100)
	mustNoErr(t, err, "sweeping")
	if queued != 1 {
		t.Fatalf("the sweep queued %d, want 1", queued)
	}
	h.drain(t, 3)
	if h.sink.count() != 1 {
		t.Fatalf("%d deliveries after the sweep", h.sink.count())
	}

	// And it must be idempotent: a second sweep finds nothing.
	again, err := h.d.SweepUndelivered(ctx, tenantA, time.Time{}, 100)
	mustNoErr(t, err, "second sweep")
	if again != 0 {
		t.Errorf("a second sweep re-queued %d events", again)
	}
}
