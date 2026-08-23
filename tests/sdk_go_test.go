package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/pkg/statushub"
)

// TestSDKVerifiesWhatTheServerSigns is the test that matters most in this
// file: the client library and the server must agree, or every customer's
// handler rejects every delivery.
func TestSDKVerifiesWhatTheServerSigns(t *testing.T) {
	body := []byte(`{"event_id":"sh_evt_1","status":"success","amount_minor":5000000}`)
	now := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)

	serverHeader := dispatch.Sign(signingSecret, body, now)
	mustNoErr(t, statushub.VerifyAt(body, serverHeader, signingSecret, now, 5*time.Minute),
		"the SDK must accept what the server produced")

	// And the reverse, so a customer's test fixtures work against the server.
	clientHeader := statushub.Sign(body, signingSecret, now)
	mustNoErr(t, dispatch.Verify(signingSecret, body, clientHeader, now, 5*time.Minute),
		"the server must accept what the SDK produced")
}

func TestSDKRejectsWhatItShould(t *testing.T) {
	body := []byte(`{"event_id":"sh_evt_1","status":"success"}`)
	now := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)
	header := statushub.Sign(body, signingSecret, now)

	cases := map[string]struct {
		body   []byte
		header string
		at     time.Time
		secret string
		want   error
	}{
		"a tampered body": {
			[]byte(`{"event_id":"sh_evt_1","status":"failed"}`), header, now, signingSecret,
			statushub.ErrBadSignature,
		},
		"the wrong secret": {body, header, now, "another-secret", statushub.ErrBadSignature},
		"a replay an hour later": {
			// The digest is still genuine. Only the window stops it.
			body, header, now.Add(time.Hour), signingSecret, statushub.ErrStale,
		},
		"no header":    {body, "", now, signingSecret, statushub.ErrNoSignature},
		"no timestamp": {body, "v1=abc", now, signingSecret, statushub.ErrMalformed},
		"no signature": {body, "t=1754903662", now, signingSecret, statushub.ErrMalformed},
		"garbage":      {body, "nonsense", now, signingSecret, statushub.ErrMalformed},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := statushub.VerifyAt(c.body, c.header, c.secret, c.at, 5*time.Minute)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestSDKToleratesRotationAndFutureElements(t *testing.T) {
	body := []byte(`{"event_id":"sh_evt_1"}`)
	now := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)

	// Two signatures during a rotation: either matching is enough, which is
	// what lets a customer rotate on their own schedule.
	multi := dispatch.SignWith([]string{"old-secret", signingSecret}, body, now)
	mustNoErr(t, statushub.VerifyAt(body, multi, signingSecret, now, 5*time.Minute), "the new secret")
	mustNoErr(t, statushub.VerifyAt(body, multi, "old-secret", now, 5*time.Minute), "the outgoing secret")

	// An unfamiliar element must be ignored, not rejected: StatusHub may add
	// one, and a handler that refuses stops working the day it does.
	withExtra := multi + ",v2=somethingnew,scheme=future"
	mustNoErr(t, statushub.VerifyAt(body, withExtra, signingSecret, now, 5*time.Minute),
		"an unknown header element must be ignored")
}

func TestSDKClockDriftIsToleratedBothWays(t *testing.T) {
	// A receiver that only tolerates the past rejects every delivery from a
	// sender running slightly fast.
	body := []byte(`{"event_id":"sh_evt_1"}`)
	now := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)
	header := statushub.Sign(body, signingSecret, now.Add(2*time.Minute))
	mustNoErr(t, statushub.VerifyAt(body, header, signingSecret, now, 5*time.Minute),
		"a slightly-future timestamp must be accepted")
}

func TestSDKHandlerIsTheWholeIntegration(t *testing.T) {
	// The forty lines the README promises, in practice.
	var got statushub.Event
	h := statushub.Handler(signingSecret, func(w http.ResponseWriter, e statushub.Event) {
		got = e
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	payload := dispatch.BuildPayload(shadowEvent("TXN-SDK"), nil)
	body, err := json.Marshal(payload)
	mustNoErr(t, err, "marshalling")

	post := func(header string) int {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, strings.NewReader(string(body)))
		mustNoErr(t, err, "building")
		if header != "" {
			req.Header.Set(statushub.SignatureHeader, header)
		}
		resp, err := srv.Client().Do(req)
		mustNoErr(t, err, "sending")
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	if code := post(dispatch.Sign(signingSecret, body, time.Now())); code != http.StatusOK {
		t.Fatalf("a genuine delivery got %d", code)
	}
	if got.TransactionRef != "TXN-SDK" || got.Status != statushub.StatusSuccess {
		t.Errorf("parsed event = %+v", got)
	}
	if got.AmountMinor != 5000000 || got.Currency != "NGN" {
		t.Errorf("amount = %d %s", got.AmountMinor, got.Currency)
	}

	// An unsigned request never reaches the handler.
	if code := post(""); code != http.StatusUnauthorized {
		t.Errorf("an unsigned delivery got %d, want 401", code)
	}
	if code := post(dispatch.Sign("wrong-secret", body, time.Now())); code != http.StatusUnauthorized {
		t.Errorf("a forged delivery got %d, want 401", code)
	}
}

func TestSDKUnknownStatusIsNotTerminal(t *testing.T) {
	// Not knowing what something is includes not knowing whether it is
	// finished. A handler that treats unknown as terminal stops watching a
	// transaction that is still moving.
	if statushub.StatusUnknown.IsTerminal() {
		t.Error("unknown must not be terminal")
	}
	if statushub.StatusPending.IsTerminal() {
		t.Error("pending must not be terminal")
	}
	for _, s := range []statushub.Status{
		statushub.StatusSuccess, statushub.StatusFailed,
		statushub.StatusReversed, statushub.StatusAbandoned,
	} {
		if !s.IsTerminal() {
			t.Errorf("%q should be terminal", s)
		}
	}
}

func TestSDKParsesTheCanonicalShape(t *testing.T) {
	// A literal payload rather than one we generated, so a change to the
	// wire format that the server and SDK both make together still fails
	// here.
	body := []byte(`{
	  "event_id": "sh_evt_1", "event_type": "payment.completed", "provider": "paystack",
	  "provider_event_id": "evt_88213", "transaction_ref": "TXN-2026-08-11-8842",
	  "status": "success", "amount_minor": 5000000, "currency": "NGN",
	  "occurred_at": "2026-08-11T09:14:31Z", "received_at": "2026-08-11T09:14:31.204Z",
	  "customer": {"ref_hash": "sha256:abc"},
	  "provider_extra": {"data.channel": "card"},
	  "mapping_complete": true
	}`)
	e, err := statushub.Parse(body)
	mustNoErr(t, err, "parsing")

	if e.EventID != "sh_evt_1" || e.TransactionRef != "TXN-2026-08-11-8842" {
		t.Errorf("event = %+v", e)
	}
	if e.AmountMinor != 5000000 {
		t.Errorf("amount = %d", e.AmountMinor)
	}
	if e.OccurredAt.UTC().Format(time.RFC3339) != "2026-08-11T09:14:31Z" {
		t.Errorf("occurred_at = %s", e.OccurredAt)
	}
	if e.Customer == nil || e.Customer.RefHash != "sha256:abc" {
		t.Errorf("customer = %+v", e.Customer)
	}
	if e.ProviderExtra["data.channel"] != "card" {
		t.Errorf("provider_extra = %v", e.ProviderExtra)
	}
}
