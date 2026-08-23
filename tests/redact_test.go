package tests

import (
	"strings"
	"testing"

	"github.com/nobledeveloper01/StatusHub/internal/redact"
)

func TestRedactRemovesCardNumbers(t *testing.T) {
	// A provider putting a full PAN in a description field is how a system
	// that is out of PCI scope by design quietly comes into scope.
	for _, body := range []string{
		`{"narration":"card 4111111111111111 declined"}`,
		`{"narration":"card 4111 1111 1111 1111 declined"}`,
		`{"narration":"card 4111-1111-1111-1111 declined"}`,
		`{"pan":"5555555555554444"}`,
		`{"pan":"378282246310005"}`, // 15-digit Amex
	} {
		r := redact.Scan([]byte(body))
		if !r.Redacted {
			t.Errorf("card data not detected in %s", body)
			continue
		}
		if strings.Contains(string(r.Body), "4111") || strings.Contains(string(r.Body), "5555555555554444") ||
			strings.Contains(string(r.Body), "378282246310005") {
			t.Errorf("card digits survived redaction: %s", r.Body)
		}
		if !strings.Contains(string(r.Body), redact.Placeholder) {
			t.Errorf("no placeholder left behind: %s", r.Body)
		}
	}
}

func TestRedactLeavesTheFieldsTheProductRunsOn(t *testing.T) {
	// A digit-length test alone would eat exactly the identifiers StatusHub
	// exists to correlate on. Luhn is what makes the check specific enough to
	// apply automatically.
	for _, body := range []string{
		`{"sessionId":"999240260811091431000012345678"}`, // 30-digit NIP session
		`{"reference":"TXN-2026-08-11-8842"}`,
		`{"account_number":"0001234567"}`,
		`{"amount":5000000,"created":1786511671}`,
		`{"phone":"+2348030000000"}`,
		`{"card":{"first_6digits":"553188","last_4digits":"2950"}}`,
	} {
		if r := redact.Scan([]byte(body)); r.Redacted {
			t.Errorf("redaction damaged a legitimate field: %s -> %s", body, r.Body)
		}
	}
}

func TestRedactDoesNotCopyWhenThereIsNothingToDo(t *testing.T) {
	body := []byte(`{"reference":"TXN-1","amount":100}`)
	r := redact.Scan(body)
	if r.Redacted || r.PANsFound != 0 {
		t.Fatalf("false positive: %+v", r)
	}
	if &r.Body[0] != &body[0] {
		t.Error("the body was copied even though nothing was replaced")
	}
}

func TestRedactSummaryNeverLeaksWhatItFound(t *testing.T) {
	// Not even a masked prefix. A first-six and last-four is still card data
	// under most readings, and no diagnostic question needs it.
	r := redact.Scan([]byte(`{"pan":"4111111111111111"}`))
	d := r.Describe()
	if strings.Contains(d, "4111") || strings.Contains(d, "1111") {
		t.Fatalf("the summary leaked card digits: %q", d)
	}
	if !strings.Contains(d, "1 card-number-shaped") {
		t.Errorf("summary = %q", d)
	}
}
