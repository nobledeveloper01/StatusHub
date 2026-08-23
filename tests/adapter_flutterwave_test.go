package tests

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/flutterwave"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

const flwSecret = "FLWSECK_TEST" + "-9f2a7c1x88420000-X"

func TestAdapterFlutterwaveSignatureVectors(t *testing.T) {
	a := flutterwave.New()
	body := fixture(t, "flutterwave", "charge.completed.json")

	t.Run("the configured secret hash is accepted", func(t *testing.T) {
		h := http.Header{"Verif-Hash": []string{flwSecret}}
		mustNoErr(t, a.Verify(h, body, flwSecret), "verifying the configured hash")
	})

	t.Run("the alternative header spelling is accepted", func(t *testing.T) {
		// Flutterwave has documented it both ways. Rejecting one spelling
		// would silently drop every event from an account configured against
		// the other page.
		h := http.Header{"Verify-Hash": []string{flwSecret}}
		mustNoErr(t, a.Verify(h, body, flwSecret), "verifying the alternative header")
	})

	t.Run("a different hash is rejected", func(t *testing.T) {
		h := http.Header{"Verif-Hash": []string{"FLWSECK_TEST-someone-elses-hash"}}
		if err := a.Verify(h, body, flwSecret); !errors.Is(err, adapter.ErrBadSignature) {
			t.Fatalf("expected ErrBadSignature, got %v", err)
		}
	})

	t.Run("an endpoint with no configured secret refuses everything", func(t *testing.T) {
		// An empty secret would otherwise accept any non-empty header, which
		// is worse than no check because it looks like one.
		h := http.Header{"Verif-Hash": []string{"anything"}}
		if err := a.Verify(h, body, ""); err == nil {
			t.Fatal("an endpoint with no secret accepted a webhook")
		}
	})

	t.Run("a missing header is rejected", func(t *testing.T) {
		if err := a.Verify(http.Header{}, body, flwSecret); !errors.Is(err, adapter.ErrNoSignature) {
			t.Fatalf("expected ErrNoSignature, got %v", err)
		}
	})

	t.Run("the scheme's weakness is documented rather than hidden", func(t *testing.T) {
		// The header does not cover the body, so a modified payload with a
		// genuine header still verifies. That is a property of Flutterwave's
		// scheme, not a defect here — but a customer choosing this provider
		// has to be told, so the adapter states it.
		tampered := []byte(strings.Replace(string(body), "8134.55", "1.00", 1))
		h := http.Header{"Verif-Hash": []string{flwSecret}}
		if err := a.Verify(h, tampered, flwSecret); err != nil {
			t.Fatalf("unexpected verification failure: %v", err)
		}
		notes := a.Describe().Notes
		if !strings.Contains(notes, "does not cover the request body") {
			t.Errorf("the weaker guarantee is not documented: %q", notes)
		}
	})
}

func TestAdapterFlutterwaveCapturedPayloads(t *testing.T) {
	a := flutterwave.New()

	t.Run("major units convert exactly", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "flutterwave", "charge.completed.json"))
		mustNoErr(t, err, "parsing charge.completed")

		// 8134.55 naira is 813455 kobo. Going via float64 gives
		// 813454.9999999999, which truncates to 813454 — one kobo short of
		// what the customer paid, on every transaction, forever.
		if ev.AmountMinor != 813455 {
			t.Fatalf("amount = %d minor units, want 813455 — the float64 path loses a kobo", ev.AmountMinor)
		}
		if ev.Currency != "NGN" {
			t.Errorf("currency = %q", ev.Currency)
		}
		if ev.Status != domain.StatusSuccess {
			t.Errorf("status = %q", ev.Status)
		}
		// The merchant's own reference, not Flutterwave's, because it is the
		// only identifier the fintech also holds.
		if ev.TransactionRef != "TXN-2026-08-11-8842" {
			t.Errorf("transaction ref = %q, want the merchant's tx_ref", ev.TransactionRef)
		}
		if ev.ProviderEventID != "4589301" {
			t.Errorf("provider event ID = %q", ev.ProviderEventID)
		}
		if !ev.MappingComplete {
			t.Error("mapping should be complete")
		}
		if got := ev.ProviderExtra["data.card.last_4digits"]; got != "2950" {
			t.Errorf("unmapped field lost: %v", got)
		}
	})

	t.Run("upper-case status values map", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "flutterwave", "transfer.completed.json"))
		mustNoErr(t, err, "parsing transfer.completed")
		if ev.Status != domain.StatusSuccess {
			t.Errorf("SUCCESSFUL did not map: %q", ev.Status)
		}
		if ev.EventType != domain.EventTransferCompleted {
			t.Errorf("event type = %q", ev.EventType)
		}
		if ev.AmountMinor != 12500000 {
			t.Errorf("amount = %d, want 12500000", ev.AmountMinor)
		}
	})

	t.Run("a failed charge", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "flutterwave", "charge.failed.json"))
		mustNoErr(t, err, "parsing charge.failed")
		if ev.Status != domain.StatusFailed {
			t.Errorf("status = %q", ev.Status)
		}
		if ev.AmountMinor != 50000 {
			t.Errorf("amount = %d, want 50000", ev.AmountMinor)
		}
	})

	t.Run("AWAITING_VALIDATION becomes unknown", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "flutterwave", "charge.unmapped_status.json"))
		mustNoErr(t, err, "parsing an unmapped status")
		if ev.Status != domain.StatusUnknown {
			t.Fatalf("status = %q, want unknown", ev.Status)
		}
		if ev.UnmappedStatus != "AWAITING_VALIDATION" {
			t.Errorf("raw value not preserved: %q", ev.UnmappedStatus)
		}
		if ev.MappingComplete {
			t.Error("mapping should be flagged incomplete")
		}
	})
}

func TestAdapterFlutterwaveDedupeKey(t *testing.T) {
	a := flutterwave.New()
	key, ok := a.DedupeKey(fixture(t, "flutterwave", "charge.completed.json"))
	if !ok || key != "4589301" {
		t.Fatalf("dedupe key = %q, ok = %v; want 4589301", key, ok)
	}
	if _, ok := a.DedupeKey([]byte(`{"event":"charge.completed"}`)); ok {
		t.Error("claimed a dedupe key from a payload with no data.id")
	}
}
