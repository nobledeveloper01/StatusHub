package tests

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/tunnel"
)

func tunnelEvent(ref string, status domain.Status) domain.CanonicalEvent {
	return domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "paystack",
		EventType: domain.EventTypeFor("payment", status), TransactionRef: ref,
		Status: status, AmountMinor: 5000000, Currency: "NGN",
		OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(),
	}
}

func TestTunnelStreamsEventsToAListener(t *testing.T) {
	// A short poll so the second, empty poll below returns promptly rather
	// than waiting out the production twenty-five seconds.
	h := tunnel.NewHub(tunnel.Options{MaxWait: 50 * time.Millisecond})
	s := h.Start(tenantA, "http://localhost:3000/hooks", domain.Filter{})

	if n := h.Publish(tunnelEvent("TXN-1", domain.StatusSuccess), []byte(`{"event_id":"1"}`), "t=1,v1=abc"); n != 1 {
		t.Fatalf("%d sessions took the event, want 1", n)
	}

	got, err := h.Poll(context.Background(), tenantA, s.ID, 10)
	mustNoErr(t, err, "polling")
	if len(got) != 1 {
		t.Fatalf("%d deliveries", len(got))
	}
	// The payload must be byte-identical to what a real destination receives,
	// signed the same way — the whole point is developing against the real
	// thing rather than an approximation.
	if string(got[0].Payload) != `{"event_id":"1"}` || got[0].Signature != "t=1,v1=abc" {
		t.Errorf("delivery = %+v", got[0])
	}

	// And it is not handed out twice.
	again, err := h.Poll(context.Background(), tenantA, s.ID, 10)
	mustNoErr(t, err, "polling again")
	if len(again) != 0 {
		t.Errorf("the same event was delivered twice")
	}
}

func TestTunnelIsScopedToOneTenant(t *testing.T) {
	h := tunnel.NewHub(tunnel.Options{})
	s := h.Start(tenantA, "http://localhost:3000", domain.Filter{})

	// Another tenant's event must never reach this session, and another
	// tenant must not be able to poll it.
	other := tunnelEvent("TXN-1", domain.StatusSuccess)
	other.TenantID = tenantB
	if n := h.Publish(other, []byte(`{}`), ""); n != 0 {
		t.Fatalf("another tenant's event reached %d sessions", n)
	}
	if _, err := h.Poll(context.Background(), tenantB, s.ID, 10); err == nil {
		t.Fatal("tenant B polled tenant A's session")
	}
}

func TestTunnelRespectsTheListenersFilter(t *testing.T) {
	// An engineer working on refunds should not be woken up by every payment.
	h := tunnel.NewHub(tunnel.Options{})
	s := h.Start(tenantA, "http://localhost:3000", domain.Filter{
		Statuses: []domain.Status{domain.StatusFailed},
	})

	h.Publish(tunnelEvent("TXN-1", domain.StatusSuccess), []byte(`{}`), "")
	h.Publish(tunnelEvent("TXN-2", domain.StatusFailed), []byte(`{}`), "")

	got, err := h.Poll(context.Background(), tenantA, s.ID, 10)
	mustNoErr(t, err, "polling")
	if len(got) != 1 {
		t.Fatalf("%d deliveries, want only the failed one", len(got))
	}
	if got[0].EventType != string(domain.EventPaymentFailed) {
		t.Errorf("delivered %q", got[0].EventType)
	}
}

func TestTunnelPollBlocksUntilAnEventArrives(t *testing.T) {
	// Long-polling is what keeps an idle laptop making two requests a minute
	// rather than sixty.
	h := tunnel.NewHub(tunnel.Options{})
	s := h.Start(tenantA, "http://localhost:3000", domain.Filter{})

	var (
		wg  sync.WaitGroup
		got []tunnel.Delivery
		err error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, err = h.Poll(context.Background(), tenantA, s.ID, 10)
	}()

	time.Sleep(50 * time.Millisecond)
	h.Publish(tunnelEvent("TXN-1", domain.StatusSuccess), []byte(`{}`), "")
	wg.Wait()

	mustNoErr(t, err, "polling")
	if len(got) != 1 {
		t.Fatalf("the blocked poll returned %d deliveries", len(got))
	}
}

func TestTunnelPollReturnsEmptyRatherThanErroringOnAQuietEndpoint(t *testing.T) {
	// An empty return is the normal case on a quiet endpoint. Treating it as
	// an error would fill a developer's terminal with noise for nothing
	// happening.
	h := tunnel.NewHub(tunnel.Options{})
	s := h.Start(tenantA, "http://localhost:3000", domain.Filter{})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got, err := h.Poll(ctx, tenantA, s.ID, 10)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a quiet poll errored: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("%d deliveries from a quiet endpoint", len(got))
	}
}

func TestTunnelDropsOldestWhenAListenerFallsBehind(t *testing.T) {
	// A developer whose handler broke ten minutes ago wants the last thirty
	// seconds of events, not the first hundred from when it broke.
	h := tunnel.NewHub(tunnel.Options{MaxQueue: 3})
	s := h.Start(tenantA, "http://localhost:3000", domain.Filter{})

	for i := 0; i < 6; i++ {
		h.Publish(tunnelEvent("TXN-"+string(rune('A'+i)), domain.StatusSuccess), []byte(`{}`), "")
	}

	queued, err := h.Queued(tenantA, s.ID)
	mustNoErr(t, err, "counting")
	if queued != 3 {
		t.Fatalf("queued %d, want the cap of 3", queued)
	}

	got, err := h.Poll(context.Background(), tenantA, s.ID, 10)
	mustNoErr(t, err, "polling")
	if len(got) != 3 {
		t.Fatalf("%d delivered", len(got))
	}
	// The three most recent, not the three oldest.
	if got[0].Event.TransactionRef != "TXN-D" {
		t.Errorf("the oldest events were kept instead of the newest: first is %s", got[0].Event.TransactionRef)
	}
}

func TestTunnelForgetsAbandonedSessions(t *testing.T) {
	// A developer closes their laptop and walks away; without this the server
	// holds their queue forever.
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	h := tunnel.NewHub(tunnel.Options{Now: clock.now})
	s := h.Start(tenantA, "http://localhost:3000", domain.Filter{})

	if len(h.Sessions(tenantA)) != 1 {
		t.Fatal("the session was not registered")
	}

	clock.advance(tunnel.MaxSessionAge + time.Minute)
	// An abandoned session stops taking events before it is swept, so its
	// queue does not grow in the meantime.
	if n := h.Publish(tunnelEvent("TXN-1", domain.StatusSuccess), []byte(`{}`), ""); n != 0 {
		t.Errorf("an abandoned session took %d events", n)
	}
	if len(h.Sessions(tenantA)) != 0 {
		t.Error("an abandoned session is still listed")
	}
	if removed := h.Sweep(); removed != 1 {
		t.Errorf("swept %d sessions, want 1", removed)
	}
	if _, err := h.Poll(context.Background(), tenantA, s.ID, 10); err == nil {
		t.Error("a swept session still polls")
	}
}

func TestTunnelTallyMatchesWhatTheDeveloperSees(t *testing.T) {
	// A developer reading "47 delivered, 2 failed" and an operator reading
	// something different in the dashboard is a confusing five minutes nobody
	// needs.
	h := tunnel.NewHub(tunnel.Options{})
	s := h.Start(tenantA, "http://localhost:3000", domain.Filter{})

	mustNoErr(t, h.Report(tenantA, s.ID, []tunnel.Outcome{
		{EventID: "1", StatusCode: 200},
		{EventID: "2", StatusCode: 200},
		{EventID: "3", StatusCode: 500},
		{EventID: "4", Error: "connection refused"},
	}), "reporting")

	sessions := h.Sessions(tenantA)
	if len(sessions) != 1 {
		t.Fatalf("%d sessions", len(sessions))
	}
	if sessions[0].Delivered != 2 || sessions[0].Failed != 2 {
		t.Errorf("tally = %d delivered, %d failed", sessions[0].Delivered, sessions[0].Failed)
	}
}

func TestTunnelDoesNotDivertProductionDeliveries(t *testing.T) {
	// Turning on `listen` in the wrong terminal must not silently break a
	// customer's live integration. Publish only offers a copy; it returns how
	// many listeners took one and changes nothing else.
	h := tunnel.NewHub(tunnel.Options{})
	ev := tunnelEvent("TXN-1", domain.StatusSuccess)

	if n := h.Publish(ev, []byte(`{}`), ""); n != 0 {
		t.Fatalf("with no listeners, Publish reported %d takers", n)
	}
	h.Start(tenantA, "http://localhost:3000", domain.Filter{})
	if n := h.Publish(ev, []byte(`{}`), ""); n != 1 {
		t.Errorf("with one listener, Publish reported %d takers", n)
	}
}
