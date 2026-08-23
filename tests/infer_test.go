package tests

import (
	"strings"
	"testing"

	"github.com/nobledeveloper01/StatusHub/internal/adapters/declarative"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// An unsupported provider's payloads, of the kind an engineer would paste in.
var acmeSamples = []declarative.Sample{
	{Name: "success", Body: `{
	  "eventId": "evt-1",
	  "data": {
	    "tx_ref": "TXN-1", "status": "SUCCESSFUL", "amount": 8134.55,
	    "currency": "NGN", "paidAt": "2026-08-11 09:14:31",
	    "customer": {"email": "tunde@example.com"}
	  }
	}`},
	{Name: "failure", Body: `{
	  "eventId": "evt-2",
	  "data": {
	    "tx_ref": "TXN-2", "status": "DECLINED", "amount": 500.00,
	    "currency": "NGN", "paidAt": "2026-08-11 10:00:00",
	    "customer": {"email": "ngozi@example.com"}
	  }
	}`},
	{Name: "pending", Body: `{
	  "eventId": "evt-3",
	  "data": {
	    "tx_ref": "TXN-3", "status": "AWAITING_SETTLEMENT", "amount": 1200.00,
	    "currency": "NGN", "paidAt": "2026-08-11 11:00:00",
	    "customer": {"email": "ibrahim@example.com"}
	  }
	}`},
}

func TestInferProducesALoadableDraft(t *testing.T) {
	p, err := declarative.Infer("acme-bank", acmeSamples)
	mustNoErr(t, err, "inferring")

	mustNoErr(t, p.Validate(), "the draft should load: "+p.Summary())

	if p.Config.Mapping.TransactionRef != "$.data.tx_ref" {
		t.Errorf("transaction_ref = %q", p.Config.Mapping.TransactionRef)
	}
	if p.Config.Mapping.ProviderEventID != "$.eventId" {
		t.Errorf("provider_event_id = %q", p.Config.Mapping.ProviderEventID)
	}
	if p.Config.Mapping.Status.Path != "$.data.status" {
		t.Errorf("status.path = %q", p.Config.Mapping.Status.Path)
	}
	if p.Config.Mapping.CustomerRef != "$.data.customer.email" {
		t.Errorf("customer_ref = %q", p.Config.Mapping.CustomerRef)
	}

	// And the draft actually parses the samples it came from.
	a, err := declarative.Compile(p.Config)
	mustNoErr(t, err, "compiling")
	ev, err := a.Parse([]byte(acmeSamples[0].Body))
	mustNoErr(t, err, "parsing the first sample")
	if ev.TransactionRef != "TXN-1" || ev.Status != domain.StatusSuccess {
		t.Errorf("parsed = %+v", ev)
	}
	if ev.AmountMinor != 813455 {
		t.Errorf("amount = %d, want 813455", ev.AmountMinor)
	}
}

func TestInferBuildsTheStatusTableFromWhatAppeared(t *testing.T) {
	// Building the table from the values that actually occurred is the
	// tedious part a machine is genuinely better at.
	p, err := declarative.Infer("acme-bank", acmeSamples)
	mustNoErr(t, err, "inferring")

	table := p.Config.Mapping.Status.Values
	if table["SUCCESSFUL"] != "success" {
		t.Errorf("SUCCESSFUL mapped to %q", table["SUCCESSFUL"])
	}
	if table["DECLINED"] != "failed" {
		t.Errorf("DECLINED mapped to %q", table["DECLINED"])
	}
	// "AWAITING_SETTLEMENT" reads as pending, and guessing that is safe
	// because pending is the non-committal answer.
	if table["AWAITING_SETTLEMENT"] != "pending" {
		t.Errorf("AWAITING_SETTLEMENT mapped to %q", table["AWAITING_SETTLEMENT"])
	}
	if len(p.StatusesSeen) != 3 {
		t.Errorf("statuses seen = %v", p.StatusesSeen)
	}
	// And the default is the only one the validator permits.
	if p.Config.Mapping.Status.Default != "unknown" {
		t.Errorf("default = %q", p.Config.Mapping.Status.Default)
	}
}

func TestInferRefusesToInventAResponseCodeMeaning(t *testing.T) {
	// A numeric code other than 00 means something specific per provider, and
	// inventing a meaning is how a fintech reverses a payment that succeeded.
	samples := []declarative.Sample{
		{Body: `{"reference":"T1","responseCode":"00","amount":100}`},
		{Body: `{"reference":"T2","responseCode":"51","amount":100}`},
		{Body: `{"reference":"T3","responseCode":"91","amount":100}`},
	}
	p, err := declarative.Infer("codes-bank", samples)
	mustNoErr(t, err, "inferring")

	table := p.Config.Mapping.Status.Values
	if table["00"] != "success" {
		t.Errorf(`"00" mapped to %q; it is the near-universal ISO-8583 success code`, table["00"])
	}
	for _, code := range []string{"51", "91"} {
		if table[code] != "unknown" {
			t.Errorf("code %q was guessed as %q; an unrecognised response code must not be assigned a meaning",
				code, table[code])
		}
	}
}

func TestInferDetectsMajorUnitsFromAFractionalPart(t *testing.T) {
	// The one amount signal that is close to conclusive.
	p, err := declarative.Infer("acme-bank", acmeSamples)
	mustNoErr(t, err, "inferring")
	if p.Config.Mapping.Amount.Unit != "major" {
		t.Fatalf("unit = %q; 8134.55 only makes sense in major units", p.Config.Mapping.Amount.Unit)
	}
	if !guessConfidence(p, "amount.unit", "high") {
		t.Error("a conclusive signal was not reported as high confidence")
	}
}

func TestInferAdmitsWhenTheAmountUnitIsAmbiguous(t *testing.T) {
	// 5000 is either fifty naira in kobo or five thousand naira. Saying so is
	// more useful than picking and sounding confident.
	samples := []declarative.Sample{
		{Body: `{"reference":"T1","status":"success","amount":5000}`},
		{Body: `{"reference":"T2","status":"success","amount":12000}`},
	}
	p, err := declarative.Infer("whole-bank", samples)
	mustNoErr(t, err, "inferring")

	if !guessConfidence(p, "amount.unit", "low") {
		t.Fatal("an ambiguous amount unit was reported as confident")
	}
	var why string
	for _, g := range p.Guesses {
		if g.Field == "amount.unit" {
			why = g.Why
		}
	}
	if !strings.Contains(why, "hundredfold") {
		t.Errorf("the warning does not state the cost of getting it wrong: %q", why)
	}
}

func TestInferRequiresATimezoneForANaiveTimestamp(t *testing.T) {
	// Read in the wrong zone, every event lands an hour from where it belongs
	// and reorders against the rest of its transaction.
	p, err := declarative.Infer("acme-bank", acmeSamples)
	mustNoErr(t, err, "inferring")

	if p.Config.Mapping.OccurredAt.Format != "2006-01-02 15:04:05" {
		t.Errorf("format = %q", p.Config.Mapping.OccurredAt.Format)
	}
	if p.Config.Mapping.OccurredAt.Timezone == "" {
		t.Fatal("a zone-free format was proposed with no timezone; the validator would refuse it")
	}
	var why string
	for _, g := range p.Guesses {
		if g.Field == "occurred_at.format" {
			why = g.Why
		}
	}
	if !strings.Contains(why, "CHANGE IT IF WRONG") {
		t.Errorf("the timezone guess is not flagged for review: %q", why)
	}
}

func TestInferIgnoresFieldsMissingFromSomeSamples(t *testing.T) {
	// A field in one payload out of three will be absent in production, and
	// mapping it produces an adapter that flags most events incomplete.
	samples := []declarative.Sample{
		{Body: `{"reference":"T1","status":"success","amount":100,"settledAt":"2026-08-11T09:00:00Z"}`},
		{Body: `{"reference":"T2","status":"failed","amount":100}`},
		{Body: `{"reference":"T3","status":"success","amount":100}`},
	}
	p, err := declarative.Infer("partial-bank", samples)
	mustNoErr(t, err, "inferring")

	if strings.Contains(p.Config.Mapping.OccurredAt.Path, "settledAt") {
		t.Fatalf("a field present in only one sample was mapped: %q", p.Config.Mapping.OccurredAt.Path)
	}
}

func TestInferSaysWhatItCouldNotFindAndWhatItCannotKnow(t *testing.T) {
	p, err := declarative.Infer("acme-bank", acmeSamples)
	mustNoErr(t, err, "inferring")

	// Verification cannot be inferred: nothing in a payload says how it was
	// signed. Saying so beats emitting a plausible guess nobody checks.
	joined := strings.Join(p.Warnings, "\n")
	if !strings.Contains(joined, "placeholder, not an inference") {
		t.Errorf("the verification placeholder is not flagged:\n%s", joined)
	}

	// Every guess carries its reasoning, so an engineer can check the
	// reasoning rather than only the result.
	for _, g := range p.Guesses {
		if g.Why == "" {
			t.Errorf("guess for %q carries no reasoning", g.Field)
		}
		if g.Confidence == "" {
			t.Errorf("guess for %q carries no confidence", g.Field)
		}
	}

	if !strings.Contains(p.Summary(), "test it against captured payloads") {
		t.Errorf("the summary does not tell the engineer what to do next: %q", p.Summary())
	}
}

func TestInferFlagsAnAmbiguousFieldChoice(t *testing.T) {
	// Several plausible fields means the guess is a coin-flip dressed as a
	// decision, and an engineer needs to know which.
	samples := []declarative.Sample{
		{Body: `{"reference":"T1","orderId":"O1","txid":"X1","status":"success","amount":100}`},
		{Body: `{"reference":"T2","orderId":"O2","txid":"X2","status":"success","amount":100}`},
	}
	p, err := declarative.Infer("ambiguous-bank", samples)
	mustNoErr(t, err, "inferring")

	if !guessConfidence(p, "transaction_ref", "low") {
		t.Fatal("three candidate reference fields produced a confident guess")
	}
	var why string
	for _, g := range p.Guesses {
		if g.Field == "transaction_ref" {
			why = g.Why
		}
	}
	if !strings.Contains(why, "Other candidates") {
		t.Errorf("the alternatives were not listed: %q", why)
	}
}

func TestInferNeedsAtLeastOneSample(t *testing.T) {
	if _, err := declarative.Infer("x", nil); err == nil {
		t.Fatal("inference with no samples succeeded")
	}
	if _, err := declarative.Infer("x", []declarative.Sample{{Body: "not json"}}); err == nil {
		t.Fatal("inference from a non-JSON sample succeeded")
	}
}

func guessConfidence(p declarative.Proposal, field, want string) bool {
	for _, g := range p.Guesses {
		if g.Field == field {
			return g.Confidence == want
		}
	}
	return false
}
