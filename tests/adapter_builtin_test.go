package tests

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/adapters"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/interswitch"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/monnify"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/nibss"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/stripe"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/jsonpath"
)

const sharedSecret = "whsec_" + "0123456789abcdef0123456789abcdef"

func sha512Hex(secret string, payload []byte) string {
	m := hmac.New(sha512.New, []byte(secret))
	m.Write(payload)
	return hex.EncodeToString(m.Sum(nil))
}

func sha256Hex(secret string, payload []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(payload)
	return hex.EncodeToString(m.Sum(nil))
}

func sha256B64(secret string, payload []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(payload)
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// ---------------------------------------------------------------- Monnify --

func TestAdapterMonnify(t *testing.T) {
	a := monnify.New()

	t.Run("signature vectors", func(t *testing.T) {
		body := fixture(t, "monnify", "transaction.completed.json")
		good := sha512Hex(sharedSecret, body)

		mustNoErr(t, a.Verify(http.Header{"Monnify-Signature": {good}}, body, sharedSecret), "genuine signature")

		tampered := []byte(strings.Replace(string(body), "50000.00", "5.00", 1))
		if err := a.Verify(http.Header{"Monnify-Signature": {good}}, tampered, sharedSecret); !errors.Is(err, adapter.ErrBadSignature) {
			t.Errorf("a tampered body verified: %v", err)
		}
		if err := a.Verify(http.Header{}, body, sharedSecret); !errors.Is(err, adapter.ErrNoSignature) {
			t.Errorf("missing header: %v", err)
		}
	})

	t.Run("a completed collection", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "monnify", "transaction.completed.json"))
		mustNoErr(t, err, "parsing")
		if ev.Status != domain.StatusSuccess {
			t.Errorf("status = %q", ev.Status)
		}
		if ev.TransactionRef != "TXN-2026-08-11-8842" {
			t.Errorf("ref = %q, want the merchant's paymentReference", ev.TransactionRef)
		}
		// amountPaid is what arrived. settlementAmount is net of fees, and
		// using it would understate every transaction by the fee.
		if ev.AmountMinor != 5000000 {
			t.Errorf("amount = %d, want 5000000 (amountPaid, not settlementAmount)", ev.AmountMinor)
		}
		// paidOn has no zone. Read as UTC it would be 09:14:31Z; read as
		// Lagos it is 08:14:31Z, which is when it actually happened.
		if got := ev.OccurredAt.Format(time.RFC3339); got != "2026-08-11T08:14:31Z" {
			t.Errorf("occurred_at = %s, want 2026-08-11T08:14:31Z — a naive timestamp was not read as Africa/Lagos", got)
		}
	})

	t.Run("a part payment is not guessed either way", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "monnify", "transaction.partial.json"))
		mustNoErr(t, err, "parsing")

		// success would credit an invoice that was not paid; failed would
		// discard money that arrived. Neither is defensible, so neither is
		// chosen.
		if ev.Status != domain.StatusUnknown {
			t.Fatalf("status = %q, want unknown for PARTIALLY_PAID", ev.Status)
		}
		// It is understood, not unmapped — so it must not raise the "new
		// unknown status" alert every time one arrives.
		if ev.UnmappedStatus != "" {
			t.Errorf("PARTIALLY_PAID was reported as unmapped; it is deliberately unknown, not unrecognised")
		}
		if ev.ProviderExtra["monnify_payment_status"] != "PARTIALLY_PAID" {
			t.Errorf("the provider's own value was not carried through: %v", ev.ProviderExtra["monnify_payment_status"])
		}
		if ev.AmountMinor != 2000000 {
			t.Errorf("amount = %d, want the 2,000,000 kobo that actually arrived", ev.AmountMinor)
		}
	})

	t.Run("a failed disbursement is a transfer", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "monnify", "disbursement.failed.json"))
		mustNoErr(t, err, "parsing")
		if ev.EventType != domain.EventTransferFailed {
			t.Errorf("event type = %q, want transfer.failed", ev.EventType)
		}
	})
}

// ------------------------------------------------------------------ NIBSS --

func TestAdapterNIBSS(t *testing.T) {
	a := nibss.New()

	// The signature covers sessionId + paymentReference + amount, not the
	// body. Recomputed here from the fixture's own fields.
	signFixture := func(t *testing.T, name string) []byte {
		t.Helper()
		body := fixture(t, "nibss", name)
		doc, err := jsonpath.Decode(body)
		mustNoErr(t, err, "decoding")
		var parts string
		for _, p := range []string{"$.sessionId", "$.paymentReference", "$.amount"} {
			s, err := jsonpath.StringAt(doc, jsonpath.MustCompile(p))
			mustNoErr(t, err, "reading "+p)
			parts += s
		}
		return []byte(parts)
	}

	t.Run("signature vectors", func(t *testing.T) {
		body := fixture(t, "nibss", "credit.success.json")
		good := sha256Hex(sharedSecret, signFixture(t, "credit.success.json"))
		mustNoErr(t, a.Verify(http.Header{"X-Nibss-Signature": {good}}, body, sharedSecret), "genuine signature")

		// Changing a signed field invalidates it.
		tampered := []byte(strings.Replace(string(body), `"50000.00"`, `"5.00"`, 1))
		if err := a.Verify(http.Header{"X-Nibss-Signature": {good}}, tampered, sharedSecret); err == nil {
			t.Error("altering the amount, which is signed, was not detected")
		}

		// Changing an unsigned field does not — which is the documented
		// weakness of a partial-coverage signature, not a defect here.
		narration := []byte(strings.Replace(string(body), "Payment for order ORD-99312", "Payment for order ORD-00000", 1))
		if err := a.Verify(http.Header{"X-Nibss-Signature": {good}}, narration, sharedSecret); err != nil {
			t.Errorf("unexpected failure on an unsigned field: %v", err)
		}
		if !strings.Contains(a.WhySourceCheckIsWeaker(), "three fields") {
			t.Error("the partial coverage is not explained to the customer")
		}
	})

	t.Run("code 00 is success", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "nibss", "credit.success.json"))
		mustNoErr(t, err, "parsing")
		if ev.Status != domain.StatusSuccess {
			t.Errorf("status = %q", ev.Status)
		}
		if ev.EventType != domain.EventTransferCompleted {
			t.Errorf("event type = %q — NIP is a transfer rail", ev.EventType)
		}
		if ev.AmountMinor != 5000000 {
			t.Errorf("amount = %d, want 5000000", ev.AmountMinor)
		}
		if ev.ProviderEventID != "999240260811091431000012345678" {
			t.Errorf("session ID not used as the provider event ID: %q", ev.ProviderEventID)
		}
		if got := ev.OccurredAt.Format(time.RFC3339); got != "2026-08-11T08:14:31Z" {
			t.Errorf("occurred_at = %s — a naive timestamp was not read as Africa/Lagos", got)
		}
		if ev.ProviderExtra["narration"] != "Payment for order ORD-99312" {
			t.Errorf("narration was lost: %v", ev.ProviderExtra["narration"])
		}
	})

	t.Run("a system malfunction is pending, not failed", func(t *testing.T) {
		// Code 96 means the outcome is not yet known. Calling it failed is
		// how a fintech reverses a transfer that later settles.
		ev, err := a.Parse(fixture(t, "nibss", "credit.pending.json"))
		mustNoErr(t, err, "parsing")
		if ev.Status != domain.StatusPending {
			t.Fatalf("code 96 mapped to %q; it must be pending — the transfer is still in flight", ev.Status)
		}
		if ev.AmountMinor != 1250050 {
			t.Errorf("amount = %d, want 1250050", ev.AmountMinor)
		}
	})

	t.Run("an unrecognised code is unknown", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "nibss", "credit.unmapped.json"))
		mustNoErr(t, err, "parsing")
		if ev.Status != domain.StatusUnknown {
			t.Errorf("status = %q, want unknown", ev.Status)
		}
		if ev.UnmappedStatus != "K7" {
			t.Errorf("raw code not preserved: %q", ev.UnmappedStatus)
		}
	})

	t.Run("published source ranges are offered but overridable", func(t *testing.T) {
		if len(a.AllowedSources()) == 0 {
			t.Fatal("no published ranges")
		}
	})
}

// ------------------------------------------------------------ Interswitch --

func TestAdapterInterswitch(t *testing.T) {
	a := interswitch.New()

	t.Run("signature vectors", func(t *testing.T) {
		body := fixture(t, "interswitch", "payment.success.json")
		signed := []byte("ISW-88213-2026" + "5000000" + "00")
		good := sha256B64(sharedSecret, signed)
		mustNoErr(t, a.Verify(http.Header{"X-Interswitch-Signature": {good}}, body, sharedSecret), "genuine signature")

		// The response code is inside the signed set, so the outcome cannot
		// be altered without invalidating the signature. That is the
		// difference from NIBSS and it is worth asserting.
		flipped := []byte(strings.Replace(string(body), `"responseCode": "00"`, `"responseCode": "51"`, 1))
		if err := a.Verify(http.Header{"X-Interswitch-Signature": {good}}, flipped, sharedSecret); err == nil {
			t.Fatal("the response code was altered without invalidating the signature")
		}

		// A hex-encoded signature must not be accepted where base64 is the
		// scheme.
		if err := a.Verify(http.Header{"X-Interswitch-Signature": {sha256Hex(sharedSecret, signed)}}, body, sharedSecret); err == nil {
			t.Error("a hex signature was accepted for a base64 scheme")
		}
	})

	t.Run("numeric currency codes are converted", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "interswitch", "payment.success.json"))
		mustNoErr(t, err, "parsing")
		// 566 in a CHAR(3) currency column would make every downstream
		// currency comparison fail silently.
		if ev.Currency != "NGN" {
			t.Fatalf("currency = %q, want NGN — the ISO numeric code was not converted", ev.Currency)
		}
		if ev.Status != domain.StatusSuccess {
			t.Errorf("status = %q", ev.Status)
		}
		if ev.AmountMinor != 5000000 {
			t.Errorf("amount = %d — Interswitch sends minor units already", ev.AmountMinor)
		}
		if ev.ProviderExtra["response_description"] != "Approved by Financial Institution" {
			t.Errorf("response description lost: %v", ev.ProviderExtra["response_description"])
		}
	})

	t.Run("a declined payment", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "interswitch", "payment.declined.json"))
		mustNoErr(t, err, "parsing")
		if ev.Status != domain.StatusFailed {
			t.Errorf("status = %q, want failed for code 51", ev.Status)
		}
	})
}

// ----------------------------------------------------------------- Stripe --

func stripeHeader(t *testing.T, body []byte, secret string, ts time.Time) string {
	t.Helper()
	signed := fmt.Sprintf("%d.%s", ts.Unix(), body)
	return fmt.Sprintf("t=%d,v1=%s", ts.Unix(), sha256Hex(secret, []byte(signed)))
}

func TestAdapterStripe(t *testing.T) {
	now := time.Date(2026, 8, 11, 9, 15, 0, 0, time.UTC)
	a := stripe.New().WithClock(func() time.Time { return now }, 5*time.Minute)
	body := fixture(t, "stripe", "payment_intent.succeeded.json")

	t.Run("a fresh signature is accepted", func(t *testing.T) {
		h := http.Header{"Stripe-Signature": {stripeHeader(t, body, sharedSecret, now)}}
		mustNoErr(t, a.Verify(h, body, sharedSecret), "verifying")
	})

	t.Run("a captured request replayed later is rejected", func(t *testing.T) {
		// The digest is still genuine — this is a real Stripe signature. Only
		// the timestamp window stops it, which is why the window is checked
		// before the digest rather than as an afterthought.
		old := now.Add(-30 * time.Minute)
		h := http.Header{"Stripe-Signature": {stripeHeader(t, body, sharedSecret, old)}}
		err := a.Verify(h, body, sharedSecret)
		if !errors.Is(err, adapter.ErrTimestampOutside) {
			t.Fatalf("a replayed request was accepted, or failed for the wrong reason: %v", err)
		}
	})

	t.Run("a clock running fast is tolerated in both directions", func(t *testing.T) {
		// Providers' clocks drift both ways. A receiver that only tolerates
		// the past rejects every event from a provider running slightly fast.
		h := http.Header{"Stripe-Signature": {stripeHeader(t, body, sharedSecret, now.Add(2*time.Minute))}}
		mustNoErr(t, a.Verify(h, body, sharedSecret), "verifying a slightly future timestamp")
	})

	t.Run("several v1 signatures let rotation work", func(t *testing.T) {
		// Stripe's own endpoint-secret rotation puts two signatures in the
		// header. Checking only the first would break it for every customer
		// who rotates.
		signed := fmt.Sprintf("%d.%s", now.Unix(), body)
		h := http.Header{"Stripe-Signature": {fmt.Sprintf("t=%d,v1=%s,v1=%s",
			now.Unix(), sha256Hex("an-old-secret", []byte(signed)), sha256Hex(sharedSecret, []byte(signed)))}}
		mustNoErr(t, a.Verify(h, body, sharedSecret), "verifying with two signatures present")
	})

	t.Run("unknown header elements are ignored rather than refused", func(t *testing.T) {
		// Stripe has added elements to this header before. An adapter that
		// rejects an unfamiliar one stops working the day they add another.
		signed := fmt.Sprintf("%d.%s", now.Unix(), body)
		h := http.Header{"Stripe-Signature": {fmt.Sprintf("t=%d,v0=ignored,v1=%s,scheme=future",
			now.Unix(), sha256Hex(sharedSecret, []byte(signed)))}}
		mustNoErr(t, a.Verify(h, body, sharedSecret), "verifying with unknown elements present")
	})

	t.Run("a tampered body is rejected", func(t *testing.T) {
		tampered := []byte(strings.Replace(string(body), "5000000", "1", 1))
		h := http.Header{"Stripe-Signature": {stripeHeader(t, body, sharedSecret, now)}}
		if err := a.Verify(h, tampered, sharedSecret); !errors.Is(err, adapter.ErrBadSignature) {
			t.Errorf("tampered body: %v", err)
		}
	})

	t.Run("a header with no timestamp is malformed", func(t *testing.T) {
		h := http.Header{"Stripe-Signature": {"v1=" + sha256Hex(sharedSecret, body)}}
		if err := a.Verify(h, body, sharedSecret); !errors.Is(err, adapter.ErrMalformedHeader) {
			t.Errorf("expected ErrMalformedHeader, got %v", err)
		}
	})

	t.Run("metadata.transaction_ref is the correlation key", func(t *testing.T) {
		ev, err := a.Parse(body)
		mustNoErr(t, err, "parsing")
		if ev.TransactionRef != "TXN-2026-08-11-8842" {
			t.Fatalf("ref = %q; the customer's own reference in metadata should win", ev.TransactionRef)
		}
		if ev.ProviderEventID != "evt_1QhX2mA1B2C3D4E5F6G7H8I9" {
			t.Errorf("provider event ID = %q", ev.ProviderEventID)
		}
		if ev.AmountMinor != 5000000 || ev.Currency != "NGN" {
			t.Errorf("amount/currency = %d %s", ev.AmountMinor, ev.Currency)
		}
		if ev.Status != domain.StatusSuccess {
			t.Errorf("status = %q", ev.Status)
		}
	})

	t.Run("a refund correlates to the payment it reverses", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "stripe", "charge.refunded.json"))
		mustNoErr(t, err, "parsing")
		if ev.EventType.Family() != "refund" {
			t.Errorf("family = %q", ev.EventType.Family())
		}
		if ev.TransactionRef != "pi_3QhX2mA1B2C3D4E5" {
			t.Errorf("a refund should correlate to its payment intent, got %q", ev.TransactionRef)
		}
	})

	t.Run("an unrecognised status is unknown", func(t *testing.T) {
		ev, err := a.Parse(fixture(t, "stripe", "payment_intent.unmapped.json"))
		mustNoErr(t, err, "parsing")
		if ev.Status != domain.StatusUnknown || ev.UnmappedStatus != "requires_settlement_confirmation" {
			t.Errorf("status = %q, unmapped = %q", ev.Status, ev.UnmappedStatus)
		}
	})
}

// ---------------------------------------------------------------- registry --

func TestAdapterRegistryShipsAllSix(t *testing.T) {
	r := adapters.New()
	want := []string{"flutterwave", "interswitch", "monnify", "nibss", "paystack", "stripe"}
	got := r.BuiltInNames()
	if len(got) != len(want) {
		t.Fatalf("registry has %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("adapter %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAdapterRegistryTenantAdaptersCannotShadowBuiltIns(t *testing.T) {
	r := adapters.New()
	// A tenant redefining "paystack" would change verification for their own
	// endpoints in a way nobody reviewing the built-in adapter would expect.
	if err := r.Register(tenantA, shadowAdapter{name: "paystack"}); err == nil {
		t.Fatal("a tenant was allowed to redefine a built-in adapter")
	}
	mustNoErr(t, r.Register(tenantA, shadowAdapter{name: "acme-bank"}), "registering a genuinely new adapter")

	if _, err := r.Get(tenantA, "acme-bank"); err != nil {
		t.Errorf("tenant A cannot use its own adapter: %v", err)
	}
	// And it is not visible to anyone else.
	if _, err := r.Get(tenantB, "acme-bank"); err == nil {
		t.Error("tenant B can use tenant A's declarative adapter")
	}
}

func TestAdapterRegistryDescribesEveryAdapter(t *testing.T) {
	for _, d := range adapters.New().Describe() {
		if d.Name == "" || d.DisplayName == "" || d.SignatureScheme == "" {
			t.Errorf("adapter %q is not documented: %+v", d.Name, d)
		}
		if len(d.KnownStatuses) == 0 {
			t.Errorf("adapter %q publishes no status mapping", d.Name)
		}
		if d.AmountUnit != "minor" && d.AmountUnit != "major" {
			t.Errorf("adapter %q does not state its amount unit: %q", d.Name, d.AmountUnit)
		}
	}
}

type shadowAdapter struct{ name string }

func (s shadowAdapter) Name() string { return s.name }
func (s shadowAdapter) Verify(http.Header, []byte, string) error {
	return adapter.ErrNoSignature
}
func (s shadowAdapter) Parse([]byte) (domain.CanonicalEvent, error) {
	return domain.CanonicalEvent{}, adapter.ErrUnparseable
}
func (s shadowAdapter) DedupeKey([]byte) (string, bool) { return "", false }
