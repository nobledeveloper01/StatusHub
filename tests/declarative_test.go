package tests

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapters/declarative"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// acmeBankConfig is the example from §4.4, which is the shape a customer
// actually writes.
const acmeBankConfig = `{
  "name": "acme-bank",
  "version": 1,
  "display_name": "Acme Bank",
  "verification": {
    "type": "hmac",
    "algorithm": "sha512",
    "source": "raw_body",
    "header": "x-acme-signature",
    "encoding": "hex"
  },
  "mapping": {
    "provider_event_id": "$.eventId",
    "transaction_ref": "$.data.reference",
    "event_family": "payment",
    "occurred_at": {
      "path": "$.data.paidAt",
      "format": "2006-01-02 15:04:05",
      "timezone": "Africa/Lagos"
    },
    "amount": {
      "path": "$.data.amount",
      "unit": "major",
      "currency_path": "$.data.currency"
    },
    "status": {
      "path": "$.data.status",
      "values": {
        "00": "success",
        "SUCCESSFUL": "success",
        "PENDING": "pending",
        "REVERSED": "reversed",
        "FAILED": "failed"
      },
      "default": "unknown"
    },
    "customer_ref": "$.data.customer.email",
    "extra_fields": { "channel": "$.data.channel" }
  }
}`

const acmePayload = `{
  "eventId": "acme-evt-77120",
  "data": {
    "reference": "TXN-2026-08-11-8842",
    "status": "SUCCESSFUL",
    "amount": 8134.55,
    "currency": "NGN",
    "paidAt": "2026-08-11 09:14:31",
    "channel": "bank_transfer",
    "customer": { "email": "tunde@example.com" },
    "internalNote": "settled batch 44"
  }
}`

func compileAcme(t *testing.T) *declarative.Adapter {
	t.Helper()
	cfg, err := declarative.Parse([]byte(acmeBankConfig))
	mustNoErr(t, err, "parsing the configuration")
	a, err := declarative.Compile(cfg)
	mustNoErr(t, err, "compiling")
	return a
}

func TestDeclarativeAdapterHandlesAProviderWeHaveNeverSeen(t *testing.T) {
	a := compileAcme(t)

	secret := "acme-signing-secret"
	m := hmac.New(sha512.New, []byte(secret))
	m.Write([]byte(acmePayload))
	sig := hex.EncodeToString(m.Sum(nil))

	mustNoErr(t, a.Verify(http.Header{"X-Acme-Signature": {sig}}, []byte(acmePayload), secret), "verifying")

	ev, err := a.Parse([]byte(acmePayload))
	mustNoErr(t, err, "parsing")

	if ev.TransactionRef != "TXN-2026-08-11-8842" {
		t.Errorf("transaction_ref = %q", ev.TransactionRef)
	}
	if ev.ProviderEventID != "acme-evt-77120" {
		t.Errorf("provider_event_id = %q", ev.ProviderEventID)
	}
	if ev.Status != domain.StatusSuccess {
		t.Errorf("status = %q", ev.Status)
	}
	// Major units, converted through the decimal text rather than a float.
	if ev.AmountMinor != 813455 {
		t.Errorf("amount = %d, want 813455", ev.AmountMinor)
	}
	// The zone was stated in the config, so 09:14:31 in Lagos is 08:14:31Z.
	if got := ev.OccurredAt.UTC().Format(time.RFC3339); got != "2026-08-11T08:14:31Z" {
		t.Errorf("occurred_at = %s, want 2026-08-11T08:14:31Z", got)
	}
	if ev.ProviderExtra["channel"] != "bank_transfer" {
		t.Errorf("named extra field lost: %v", ev.ProviderExtra["channel"])
	}
	// And an unnamed field is still carried, because nothing is dropped.
	if ev.ProviderExtra["data.internalNote"] != "settled batch 44" {
		t.Errorf("unnamed field lost: %v", ev.ProviderExtra["data.internalNote"])
	}

	key, ok := a.DedupeKey([]byte(acmePayload))
	if !ok || key != "acme-evt-77120" {
		t.Errorf("dedupe key = %q, %v", key, ok)
	}
}

func TestDeclarativeAdapterRefusesToGuessAnUnmappedStatus(t *testing.T) {
	// The single most important rule in the file. An adapter that could
	// default an unrecognised status to "failed" would, sooner or later,
	// cause a fintech to reverse a payment that succeeded — so it is not
	// configurable.
	for _, bad := range []string{"failed", "success", "pending", "reversed", "abandoned"} {
		cfg, err := declarative.Parse([]byte(strings.Replace(acmeBankConfig, `"default": "unknown"`, `"default": "`+bad+`"`, 1)))
		mustNoErr(t, err, "parsing")
		err = cfg.Validate()
		if !errors.Is(err, declarative.ErrUnsafeDefault) {
			t.Errorf("default %q was accepted: %v", bad, err)
		}
	}

	// And at runtime an unlisted value becomes unknown with the original
	// preserved.
	a := compileAcme(t)
	ev, err := a.Parse([]byte(strings.Replace(acmePayload, `"SUCCESSFUL"`, `"PART_SETTLED"`, 1)))
	mustNoErr(t, err, "parsing")
	if ev.Status != domain.StatusUnknown || ev.UnmappedStatus != "PART_SETTLED" {
		t.Fatalf("status = %q, unmapped = %q", ev.Status, ev.UnmappedStatus)
	}
	if ev.MappingComplete {
		t.Error("an unmapped status should flag the mapping incomplete")
	}
}

func TestDeclarativeAdapterRequiresAnAmountUnit(t *testing.T) {
	// Assuming minor units for a provider that sends major ones divides every
	// amount by a hundred; assuming the reverse multiplies it. There is no
	// safe default, so there is no default.
	cfg, err := declarative.Parse([]byte(strings.Replace(acmeBankConfig, `"unit": "major",`, ``, 1)))
	mustNoErr(t, err, "parsing")
	if err := cfg.Validate(); !errors.Is(err, declarative.ErrNoAmountUnit) {
		t.Fatalf("an amount mapping with no unit was accepted: %v", err)
	}
}

func TestDeclarativeAdapterRequiresAStatedTimezone(t *testing.T) {
	// A naive timestamp read in the wrong zone puts an event an hour from
	// where it belongs, which reorders it against everything else on the same
	// transaction.
	cfg, err := declarative.Parse([]byte(strings.Replace(acmeBankConfig, `"timezone": "Africa/Lagos"`, `"timezone": ""`, 1)))
	mustNoErr(t, err, "parsing")
	if err := cfg.Validate(); !errors.Is(err, declarative.ErrNoTimezone) {
		t.Fatalf("a zone-free format with no timezone was accepted: %v", err)
	}

	// A format that carries its own offset needs no configured zone.
	withOffset := strings.Replace(acmeBankConfig, `"format": "2006-01-02 15:04:05",`, `"format": "2006-01-02T15:04:05Z07:00",`, 1)
	withOffset = strings.Replace(withOffset, `"timezone": "Africa/Lagos"`, `"timezone": ""`, 1)
	cfg2, err := declarative.Parse([]byte(withOffset))
	mustNoErr(t, err, "parsing")
	mustNoErr(t, cfg2.Validate(), "a self-describing format should need no timezone")
}

func TestDeclarativeAdapterRejectsUnboundedExpressions(t *testing.T) {
	// An uploaded adapter is data a customer controls, running on the
	// normalisation path. Every construct that can backtrack or recurse is a
	// denial of service delivered through a configuration form (§10).
	for _, bad := range []string{"$..reference", "$.data.items[*].ref", "$.a.b.c.d.e.f.g.h.i.j.k.l.m"} {
		cfg, err := declarative.Parse([]byte(strings.Replace(acmeBankConfig, `"$.data.reference"`, `"`+bad+`"`, 1)))
		mustNoErr(t, err, "parsing")
		if err := cfg.Validate(); err == nil {
			t.Errorf("path %q was accepted", bad)
		}
	}
}

func TestDeclarativeAdapterRejectsTypos(t *testing.T) {
	// A customer who wrote transactionRef instead of transaction_ref should
	// be told, not have their adapter silently ignore the mapping and flag
	// every event incomplete.
	_, err := declarative.Parse([]byte(`{"name":"x","verification":{"type":"hmac","header":"h"},
		"mapping":{"transactionRef":"$.ref","status":{"path":"$.s","values":{"ok":"success"}}}}`))
	if err == nil {
		t.Fatal("an unknown configuration field was accepted silently")
	}
}

func TestDeclarativeAdapterRejectsControlsThatOnlyLookLikeControls(t *testing.T) {
	// source_only with no ranges accepts everything while appearing to check
	// something, which is worse than having no check at all.
	_, err := declarative.Parse([]byte(`{"name":"x","verification":{"type":"source_only"},
		"mapping":{"transaction_ref":"$.ref","status":{"path":"$.s","values":{"ok":"success"}}}}`))
	mustNoErr(t, err, "parsing")
	cfg, _ := declarative.Parse([]byte(`{"name":"x","verification":{"type":"source_only"},
		"mapping":{"transaction_ref":"$.ref","status":{"path":"$.s","values":{"ok":"success"}}}}`))
	if err := cfg.Validate(); err == nil {
		t.Fatal("source_only with no allowed ranges was accepted")
	}
}

func TestDeclarativeAdapterSignedFieldsScheme(t *testing.T) {
	// Several real providers sign a concatenation of named fields rather than
	// the body. It has to be supported, and its weakness has to be surfaced.
	const cfgJSON = `{
      "name": "fields-bank",
      "verification": {
        "type": "hmac", "algorithm": "sha256", "encoding": "hex",
        "header": "x-fb-signature", "source": "fields",
        "fields": ["$.ref", "$.amount", "$.status"]
      },
      "mapping": {
        "transaction_ref": "$.ref",
        "amount": { "path": "$.amount", "unit": "minor", "default_currency": "NGN" },
        "status": { "path": "$.status", "values": { "OK": "success", "NO": "failed" } }
      }
    }`
	cfg, err := declarative.Parse([]byte(cfgJSON))
	mustNoErr(t, err, "parsing")
	a, err := declarative.Compile(cfg)
	mustNoErr(t, err, "compiling")

	body := []byte(`{"ref":"TXN-9","amount":"5000","status":"OK","note":"unsigned"}`)
	sig := sha256Hex("fb-secret", []byte("TXN-9"+"5000"+"OK"))
	mustNoErr(t, a.Verify(http.Header{"X-Fb-Signature": {sig}}, body, "fb-secret"), "verifying")

	// Altering a signed field is caught.
	if err := a.Verify(http.Header{"X-Fb-Signature": {sig}},
		[]byte(`{"ref":"TXN-9","amount":"1","status":"OK","note":"unsigned"}`), "fb-secret"); err == nil {
		t.Error("an altered signed field verified")
	}
	// Altering an unsigned one is not — which is the documented weakness, and
	// the test runner must warn about it.
	if err := a.Verify(http.Header{"X-Fb-Signature": {sig}},
		[]byte(`{"ref":"TXN-9","amount":"5000","status":"OK","note":"tampered"}`), "fb-secret"); err != nil {
		t.Errorf("unexpected failure on an unsigned field: %v", err)
	}
}

func TestDeclarativeTestRunnerWarnsBeforeActivation(t *testing.T) {
	// The point of a dry run is not a green tick. It is the warnings.
	const thin = `{
      "name": "thin-bank",
      "verification": { "type": "hmac", "header": "x-thin-signature" },
      "mapping": {
        "transaction_ref": "$.ref",
        "status": { "path": "$.status", "values": { "OK": "success" } }
      }
    }`
	cfg, err := declarative.Parse([]byte(thin))
	mustNoErr(t, err, "parsing")

	res := declarative.Test(cfg, declarative.TestRequest{
		Payloads: []declarative.Sample{
			{Name: "success", Body: `{"ref":"TXN-1","status":"OK"}`},
			{Name: "something new", Body: `{"ref":"TXN-2","status":"SETTLING"}`},
		},
	})
	if !res.Valid {
		t.Fatalf("the configuration should compile: %s", res.Error)
	}
	if len(res.Samples) != 2 || !res.Samples[0].Parsed {
		t.Fatalf("samples = %+v", res.Samples)
	}

	joined := strings.Join(res.Warnings, "\n")
	for _, want := range []string{
		"no provider_event_id", // will duplicate on the provider's first retry
		"no occurred_at",       // times shown will be ours, not the provider's
		"no amount is mapped",  //
		"no timestamp header",  // replayable indefinitely
		"SETTLING",             // a status the samples contain and the mapping does not
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the dry run did not warn about %q:\n%s", want, joined)
		}
	}

	// And it must name the fields it could not fill, per sample.
	if len(res.Samples[0].MissingFields) == 0 {
		t.Error("no missing fields reported for a mapping that fills almost nothing")
	}
	if res.Samples[1].UnmappedStatus != "SETTLING" {
		t.Errorf("unmapped status = %q", res.Samples[1].UnmappedStatus)
	}
}

func TestDeclarativeTestRunnerActivatesNothing(t *testing.T) {
	// A dry run must be exactly that. It touches no storage and registers
	// nothing, so a broken adapter cannot affect live traffic by being tested.
	cfg, err := declarative.Parse([]byte(acmeBankConfig))
	mustNoErr(t, err, "parsing")
	res := declarative.Test(cfg, declarative.TestRequest{
		Payloads: []declarative.Sample{{Body: acmePayload}},
		Secret:   "acme-signing-secret",
	})
	if !res.Valid || !res.Samples[0].Parsed {
		t.Fatalf("result = %+v", res)
	}
	// Verification was requested but no signature header was supplied, so it
	// must report false rather than quietly skipping the check.
	if res.Samples[0].Verified == nil || *res.Samples[0].Verified {
		t.Error("verification with no signature header should report a failure, not be skipped")
	}

	// The result must be renderable, since the dashboard shows it.
	if _, err := json.Marshal(res); err != nil {
		t.Errorf("the test result does not serialise: %v", err)
	}
}

func TestDeclarativeAdapterConfigSizeIsBounded(t *testing.T) {
	big := `{"name":"x","notes":"` + strings.Repeat("a", 70*1024) + `"}`
	if _, err := declarative.Parse([]byte(big)); !errors.Is(err, declarative.ErrTooLarge) {
		t.Fatalf("an oversized configuration was accepted: %v", err)
	}
}
