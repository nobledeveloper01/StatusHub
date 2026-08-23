package tests

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/tunnel"
)

func TestListenAPIStreamsOverHTTP(t *testing.T) {
	h := newAPIHarness(t)

	resp, started := h.do(t, h.engineerA, http.MethodPost, "/v1/listen", map[string]any{
		"forward": "http://localhost:3000/hooks",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("starting a session = %d: %v", resp.StatusCode, started)
	}
	session, _ := started["session_id"].(string)
	if session == "" {
		t.Fatal("no session id returned")
	}
	// Stated in the response, because a developer's first worry is whether
	// turning this on breaks their live integration.
	note, _ := started["note"].(string)
	if note == "" {
		t.Error("the response does not say that events are copied rather than diverted")
	}

	// Publish through the hub the API is wired to.
	ev := domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "paystack",
		EventType: domain.EventPaymentCompleted, TransactionRef: "TXN-LISTEN",
		Status: domain.StatusSuccess, AmountMinor: 5000000, Currency: "NGN",
		OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(),
	}
	if n := h.tunnel.Publish(ev, []byte(`{"event_id":"x"}`), "t=1,v1=abc"); n != 1 {
		t.Fatalf("%d sessions took the event", n)
	}

	resp, polled := h.do(t, h.engineerA, http.MethodGet, "/v1/listen/"+session+"/poll?max=10", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("polling = %d: %v", resp.StatusCode, polled)
	}
	raw, _ := json.Marshal(polled["deliveries"])
	var deliveries []tunnel.Delivery
	mustNoErr(t, json.Unmarshal(raw, &deliveries), "decoding deliveries")
	if len(deliveries) != 1 {
		t.Fatalf("%d deliveries", len(deliveries))
	}
	if deliveries[0].Signature != "t=1,v1=abc" {
		t.Errorf("the signature was not forwarded: %q", deliveries[0].Signature)
	}

	// Reporting keeps the CLI's tally and the dashboard's the same.
	resp, _ = h.do(t, h.engineerA, http.MethodPost, "/v1/listen/"+session+"/report", map[string]any{
		"outcomes": []map[string]any{{"event_id": deliveries[0].EventID, "status_code": 200}},
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("reporting = %d", resp.StatusCode)
	}

	_, list := h.do(t, h.readerA, http.MethodGet, "/v1/listen", nil)
	sessions, _ := list["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("%d sessions listed", len(sessions))
	}
	// Visible to the whole team: an operator should be able to see that
	// somebody's laptop is receiving live production events.
	first, _ := sessions[0].(map[string]any)
	if first["forward"] != "http://localhost:3000/hooks" {
		t.Errorf("the listing does not show where events are going: %v", first)
	}
	if first["delivered"] != float64(1) {
		t.Errorf("delivered = %v, want 1", first["delivered"])
	}

	resp, _ = h.do(t, h.engineerA, http.MethodDelete, "/v1/listen/"+session, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("stopping = %d", resp.StatusCode)
	}
}

func TestListenAPIRequiresEngineerRole(t *testing.T) {
	// Streaming live production payloads to an arbitrary machine is a
	// data-egress decision, not a read.
	h := newAPIHarness(t)
	resp, _ := h.do(t, h.readerA, http.MethodPost, "/v1/listen", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a read-only key started a listen session: %d", resp.StatusCode)
	}
	resp, _ = h.do(t, h.supportA, http.MethodPost, "/v1/listen", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a support key started a listen session: %d", resp.StatusCode)
	}
}

func TestListenAPIExpiredSessionSaysSo(t *testing.T) {
	// Gone rather than forbidden: the developer's laptop slept, and the CLI
	// should start a new session rather than treat this as a permissions
	// problem.
	h := newAPIHarness(t)
	resp, body := h.do(t, h.engineerA, http.MethodGet, "/v1/listen/lsn_nonexistent/poll", nil)
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("polling an unknown session = %d, want 410: %v", resp.StatusCode, body)
	}
	msg, _ := body["error"].(string)
	if msg == "" {
		t.Error("no explanation of what to do")
	}
}

func TestListenAPIIsTenantScoped(t *testing.T) {
	h := newAPIHarness(t)
	_, started := h.do(t, h.engineerA, http.MethodPost, "/v1/listen", nil)
	session, _ := started["session_id"].(string)

	// Tenant B must not be able to poll it, and must not see it listed.
	resp, _ := h.do(t, h.ownerB, http.MethodGet, "/v1/listen/"+session+"/poll", nil)
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("tenant B polled tenant A's session: %d", resp.StatusCode)
	}
	_, list := h.do(t, h.ownerB, http.MethodGet, "/v1/listen", nil)
	if sessions, _ := list["sessions"].([]any); len(sessions) != 0 {
		t.Errorf("tenant B sees %d of tenant A's sessions", len(sessions))
	}
}
