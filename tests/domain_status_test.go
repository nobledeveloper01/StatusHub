package tests

import (
	"testing"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

func TestStatusIsAClosedSet(t *testing.T) {
	for _, s := range []domain.Status{
		domain.StatusPending, domain.StatusSuccess, domain.StatusFailed,
		domain.StatusReversed, domain.StatusAbandoned, domain.StatusUnknown,
	} {
		if !s.Valid() {
			t.Errorf("%q should be valid", s)
		}
	}
	// Anything read back from storage that is not one of the six is a row
	// written by a newer binary, and must fail loudly rather than flow on as
	// free text.
	for _, s := range []domain.Status{"", "SUCCESS", "successful", "part_settled", "completed"} {
		if s.Valid() {
			t.Errorf("%q should not be valid", s)
		}
		if _, err := domain.ParseStatus(string(s)); err == nil {
			t.Errorf("ParseStatus(%q) accepted an unrecognised value", s)
		}
	}
}

func TestUnknownIsNotTerminal(t *testing.T) {
	// Treating unknown as finished is the same mistake as mapping it to
	// failed: it asserts we know the transaction's outcome when we do not.
	if domain.StatusUnknown.IsTerminal() {
		t.Error("unknown must not be terminal — we do not know that it is finished")
	}
	if domain.StatusPending.IsTerminal() {
		t.Error("pending must not be terminal")
	}
	for _, s := range []domain.Status{domain.StatusSuccess, domain.StatusFailed, domain.StatusReversed, domain.StatusAbandoned} {
		if !s.IsTerminal() {
			t.Errorf("%q should be terminal", s)
		}
	}
}

func TestEventTypeDerivation(t *testing.T) {
	cases := []struct {
		family string
		status domain.Status
		want   domain.EventType
	}{
		{"payment", domain.StatusSuccess, domain.EventPaymentCompleted},
		{"payment", domain.StatusPending, domain.EventPaymentPending},
		{"payment", domain.StatusFailed, domain.EventPaymentFailed},
		{"payment", domain.StatusReversed, domain.EventPaymentReversed},
		{"payment", domain.StatusAbandoned, domain.EventPaymentAbandoned},
		{"transfer", domain.StatusSuccess, domain.EventTransferCompleted},
		{"refund", domain.StatusSuccess, domain.EventRefundCompleted},

		// A dispute is opened and later resolved. It is never "completed"
		// and never "abandoned", so it does not go through the payment
		// vocabulary.
		{"chargeback", domain.StatusPending, domain.EventChargebackOpened},
		{"chargeback", domain.StatusSuccess, domain.EventChargebackResolved},

		// An unknown status must never produce a confident event type.
		{"payment", domain.StatusUnknown, domain.EventUnknown},
		{"transfer", domain.StatusUnknown, domain.EventUnknown},

		// A family with no such combination falls back rather than inventing
		// an event type nothing downstream can switch on.
		{"refund", domain.StatusAbandoned, domain.EventUnknown},
		{"nonsense", domain.StatusSuccess, domain.EventUnknown},
	}
	for _, c := range cases {
		if got := domain.EventTypeFor(c.family, c.status); got != c.want {
			t.Errorf("EventTypeFor(%q, %q) = %q, want %q", c.family, c.status, got, c.want)
		}
	}
}

func TestEventTypeFamily(t *testing.T) {
	if got := domain.EventPaymentCompleted.Family(); got != "payment" {
		t.Errorf("family = %q", got)
	}
	if got := domain.EventUnknown.Family(); got != "unknown" {
		t.Errorf("family of a bare type = %q", got)
	}
}
