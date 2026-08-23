package tests

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/paystack"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

const paystackSecret = "sk_test_" + "0123456789abcdef0123456789abcdef01234567"

// paystackSign computes the expected signature independently of the code
// under test. Verifying against our own Sign helper would only prove the
// helper agrees with itself; this recomputes it from crypto/hmac directly, so
// the test fails if the scheme drifts.
func paystackSign(body []byte, secret string) string {
	m := hmac.New(sha512.New, []byte(secret))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func TestAdapterPaystackSignatureVectors(t *testing.T) {
	a := paystack.New()
	body := fixture(t, "paystack", "charge.success.json")
	good := paystackSign(body, paystackSecret)

	t.Run("valid signature is accepted", func(t *testing.T) {
		h := http.Header{paystack.Header: []string{good}}
		mustNoErr(t, a.Verify(h, body, paystackSecret), "verifying a genuine signature")
	})

	t.Run("upper-case hex is accepted", func(t *testing.T) {
		// Comparison is on decoded bytes, so a provider that changes its hex
		// casing does not silently stop every event from that account.
		h := http.Header{paystack.Header: []string{strings.ToUpper(good)}}
		mustNoErr(t, a.Verify(h, body, paystackSecret), "verifying an upper-cased signature")
	})

	t.Run("a modified body is rejected", func(t *testing.T) {
		tampered := append([]byte(nil), body...)
		// Flip the amount from 5000000 to 9000000: the exact attack the
		// signature exists to stop.
		tampered = []byte(strings.Replace(string(tampered), "5000000", "9000000", 1))
		h := http.Header{paystack.Header: []string{good}}
		err := a.Verify(h, tampered, paystackSecret)
		if !errors.Is(err, adapter.ErrBadSignature) {
			t.Fatalf("a tampered body verified, or failed for the wrong reason: %v", err)
		}
	})

	t.Run("the wrong secret is rejected", func(t *testing.T) {
		h := http.Header{paystack.Header: []string{paystackSign(body, "sk_test_wrong")}}
		if err := a.Verify(h, body, paystackSecret); !errors.Is(err, adapter.ErrBadSignature) {
			t.Fatalf("a signature from another secret verified: %v", err)
		}
	})

	t.Run("a missing header is rejected as missing, not as wrong", func(t *testing.T) {
		if err := a.Verify(http.Header{}, body, paystackSecret); !errors.Is(err, adapter.ErrNoSignature) {
			t.Fatalf("expected ErrNoSignature, got %v", err)
		}
	})

	t.Run("a truncated signature is rejected", func(t *testing.T) {
		h := http.Header{paystack.Header: []string{good[:len(good)-2]}}
		if err := a.Verify(h, body, paystackSecret); err == nil {
			t.Fatal("a truncated signature verified")
		}
	})

	t.Run("an empty signature is rejected", func(t *testing.T) {
		h := http.Header{paystack.Header: []string{""}}
		if err := a.Verify(h, body, paystackSecret); !errors.Is(err, adapter.ErrNoSignature) {
			t.Fatalf("expected ErrNoSignature, got %v", err)
		}
	})
}

func TestAdapterPaystackCapturedPayloads(t *testing.T) {
	a := paystack.New()

	t.Run("successful card charge", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "paystack", "charge.success.json"))
		mustNoErr(t, err, "parsing charge.success")

		if ev.TransactionRef != "TXN-2026-08-11-8842" {
			t.Errorf("transaction ref = %q", ev.TransactionRef)
		}
		if ev.Status != domain.StatusSuccess {
			t.Errorf("status = %q, want success", ev.Status)
		}
		if ev.EventType != domain.EventPaymentCompleted {
			t.Errorf("event type = %q, want payment.completed", ev.EventType)
		}
		// Paystack sends kobo. Fifty thousand naira is 5,000,000 kobo, and it
		// must arrive as exactly that — not multiplied again.
		if ev.AmountMinor != 5000000 {
			t.Errorf("amount = %d minor units, want 5000000", ev.AmountMinor)
		}
		if ev.Currency != "NGN" {
			t.Errorf("currency = %q", ev.Currency)
		}
		if !ev.MappingComplete {
			t.Errorf("mapping should be complete for a payload with every field present")
		}
		if ev.OccurredAt.IsZero() {
			t.Error("occurred_at was not populated from paid_at")
		}
		if ev.OccurredAt.Location().String() != "UTC" {
			t.Errorf("occurred_at is in %s, must be UTC", ev.OccurredAt.Location())
		}
		// Nothing the provider sent may be dropped (§3.2 B4).
		if got := ev.ProviderExtra["data.authorization.last4"]; got != "4081" {
			t.Errorf("unmapped field lost: data.authorization.last4 = %v", got)
		}
		if got := ev.ProviderExtra["data.metadata.order_id"]; got != "ORD-99312" {
			t.Errorf("unmapped field lost: data.metadata.order_id = %v", got)
		}
		if _, present := ev.ProviderExtra["data.reference"]; present {
			t.Error("a claimed field was duplicated into provider_extra")
		}
	})

	t.Run("failed charge", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "paystack", "charge.failed.json"))
		mustNoErr(t, err, "parsing charge.failed")
		if ev.Status != domain.StatusFailed {
			t.Errorf("status = %q, want failed", ev.Status)
		}
		if ev.EventType != domain.EventPaymentFailed {
			t.Errorf("event type = %q", ev.EventType)
		}
		// No paid_at on a failure, so created_at stands in rather than the
		// event arriving with a zero timestamp.
		if ev.OccurredAt.IsZero() {
			t.Error("occurred_at should fall back to created_at")
		}
	})

	t.Run("transfer maps to the transfer family", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "paystack", "transfer.success.json"))
		mustNoErr(t, err, "parsing transfer.success")
		if ev.EventType != domain.EventTransferCompleted {
			t.Errorf("event type = %q, want transfer.completed", ev.EventType)
		}
		if ev.AmountMinor != 12500000 {
			t.Errorf("amount = %d", ev.AmountMinor)
		}
	})

	t.Run("a dispute correlates to the disputed transaction", func(t *testing.T) {
		// The reference is nested one level deeper on disputes. A chargeback
		// that cannot be correlated back to its payment is the single event a
		// fintech most needs correlated.
		ev, err := a.Parse(fixture(t, "paystack", "dispute.create.json"))
		mustNoErr(t, err, "parsing dispute.create")
		if ev.TransactionRef != "TXN-2026-08-11-8842" {
			t.Errorf("dispute did not correlate: ref = %q", ev.TransactionRef)
		}
		if ev.EventType.Family() != "chargeback" {
			t.Errorf("event family = %q, want chargeback", ev.EventType.Family())
		}
	})

	t.Run("an unmapped status becomes unknown and is never guessed", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "paystack", "charge.unmapped_status.json"))
		mustNoErr(t, err, "parsing an unmapped status")

		// This is the assertion the product's correctness rests on. Mapping
		// "part_settled" to failed would have a fintech reverse a payment
		// that partly succeeded.
		if ev.Status != domain.StatusUnknown {
			t.Fatalf("status = %q, want unknown — an unrecognised provider value must never be guessed", ev.Status)
		}
		if ev.UnmappedStatus != "part_settled" {
			t.Errorf("the provider's own value was not preserved: %q", ev.UnmappedStatus)
		}
		if ev.MappingComplete {
			t.Error("an unmapped status must mark the mapping incomplete")
		}
		if ev.EventType != domain.EventUnknown {
			t.Errorf("event type = %q, want unknown", ev.EventType)
		}
	})

	t.Run("a payload with no reference is refused", func(t *testing.T) {
		_, err := a.Parse([]byte(`{"event":"charge.success","data":{"status":"success","amount":100}}`))
		if !errors.Is(err, adapter.ErrNoTransaction) {
			t.Fatalf("expected ErrNoTransaction, got %v", err)
		}
	})

	t.Run("malformed JSON is refused rather than partly parsed", func(t *testing.T) {
		_, err := a.Parse([]byte(`{"event":"charge.success","data":{`))
		if !errors.Is(err, adapter.ErrUnparseable) {
			t.Fatalf("expected ErrUnparseable, got %v", err)
		}
	})
}

func TestAdapterPaystackDedupeKey(t *testing.T) {
	a := paystack.New()
	// Paystack genuinely supplies no per-event identifier. Reporting false is
	// the honest answer and routes the caller to body-hash deduplication.
	if _, ok := a.DedupeKey(fixture(t, "paystack", "charge.success.json")); ok {
		t.Fatal("the Paystack adapter claimed an event ID it cannot have")
	}
}

func TestAdapterPaystackDescribesItself(t *testing.T) {
	d := paystack.New().Describe()
	if d.Name != "paystack" || d.AmountUnit != "minor" {
		t.Fatalf("description is wrong: %+v", d)
	}
	if d.KnownStatuses["success"] != "success" || d.KnownStatuses["abandoned"] != "abandoned" {
		t.Errorf("known statuses are not exposed: %v", d.KnownStatuses)
	}
}
