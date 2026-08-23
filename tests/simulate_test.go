package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapters"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/receive"
	"github.com/nobledeveloper01/StatusHub/internal/secret"
	"github.com/nobledeveloper01/StatusHub/internal/simulate"
)

// TestSimulatorSignaturesVerifyAgainstEveryAdapter is the test that stops the
// simulator from being worse than nothing.
//
// A simulator whose signing drifts from an adapter's verification produces a
// green tick for an integration that does not work, and the operator only
// finds out when a real payment goes missing. This drives every sample
// through the real receiver, with the real adapter, and asserts a 200.
func TestSimulatorSignaturesVerifyAgainstEveryAdapter(t *testing.T) {
	ctx := context.Background()
	const providerSecret = "simulator-test-secret"

	for _, provider := range []string{"paystack", "flutterwave", "nibss", "monnify", "interswitch", "stripe"} {
		t.Run(provider, func(t *testing.T) {
			s := memStore(t)
			ep := domain.Endpoint{
				ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: provider,
				Environment: domain.EnvTest, ReceiverToken: domain.NewToken(),
				SecretRef: testSecretRef, AdapterName: provider, Enabled: true,
				// NIBSS gates on source address as well as signature, and no
				// developer machine is in a provider's published egress
				// range. Overriding the ranges per endpoint is exactly what
				// an operator has to do to simulate against one — which is
				// why the override exists at all.
				AllowedSourceCIDRs: []string{"127.0.0.0/8", "::1/128"},
			}
			mustNoErr(t, s.CreateEndpoint(ctx, ep), "creating the endpoint")

			secrets := secret.NewStatic()
			secrets.Set(testSecretRef, providerSecret)

			r := receive.New(receive.Options{
				Store: s, Registry: adapters.New(), Secrets: secrets,
			})
			srv := httptest.NewServer(r.Handler())
			defer srv.Close()

			samples, err := simulate.List(provider)
			mustNoErr(t, err, "listing samples")
			if len(samples) == 0 {
				t.Fatalf("no samples for %s", provider)
			}

			for _, sample := range samples {
				res, err := simulate.Send(ctx, srv.Client(), srv.URL+ep.ReceiverPath(slugA),
					sample, providerSecret, time.Now().UTC())
				mustNoErr(t, err, "sending "+sample.Name)
				if res.StatusCode != http.StatusOK {
					t.Errorf("%s/%s got %d: %s\n%s",
						provider, sample.Name, res.StatusCode, res.Body, res.Explain())
				}
			}

			// And every one was stored with a valid signature, rather than
			// stored-and-flagged.
			failures, err := s.ListSignatureFailures(ctx, tenantA, ep.ID, time.Time{}, 100)
			mustNoErr(t, err, "listing signature failures")
			if len(failures) != 0 {
				t.Errorf("%d simulated events failed verification", len(failures))
			}
		})
	}
}

func TestSimulatorFreshensTimestampsSoStripeAccepts(t *testing.T) {
	// Stripe's five-minute window would reject every stored sample as a
	// replay. Without freshening, the operator's first experience of the
	// simulator is a 401 that looks like a configuration problem.
	s, err := simulate.Get("stripe", "payment_intent.succeeded")
	mustNoErr(t, err, "getting the sample")

	now := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	fresh := simulate.Freshen(s, now)

	var doc map[string]any
	mustNoErr(t, json.Unmarshal(fresh, &doc), "decoding")
	created, _ := doc["created"].(float64)
	if int64(created) != now.Unix() {
		t.Fatalf("created = %v, want %d", created, now.Unix())
	}

	// The shape must be untouched: the sample's whole purpose is to exercise
	// the adapter against the real payload structure.
	if doc["type"] != "payment_intent.succeeded" {
		t.Errorf("freshening altered the event type: %v", doc["type"])
	}
	obj, _ := doc["data"].(map[string]any)
	inner, _ := obj["object"].(map[string]any)
	if inner["status"] != "succeeded" {
		t.Errorf("freshening altered the status: %v", inner["status"])
	}
}

func TestSimulatorKeepsEachProvidersOwnFormat(t *testing.T) {
	// Rewriting a Monnify timestamp into RFC 3339 would test a format Monnify
	// never sends, and would silently stop exercising the Africa/Lagos path.
	s, err := simulate.Get("monnify", "transaction.completed")
	mustNoErr(t, err, "getting the sample")
	fresh := simulate.Freshen(s, time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC))

	var doc map[string]any
	mustNoErr(t, json.Unmarshal(fresh, &doc), "decoding")
	data, _ := doc["eventData"].(map[string]any)
	paidOn, _ := data["paidOn"].(string)
	// Monnify's format: naive, space-separated, with milliseconds.
	if _, err := time.Parse("2006-01-02 15:04:05.000", paidOn); err != nil {
		t.Fatalf("paidOn = %q, which is not Monnify's own format: %v", paidOn, err)
	}
}

func TestSimulatorExplainsFailuresUsefully(t *testing.T) {
	// A bare status code sends people to the source. Each failure that
	// matters has one likely cause, and naming it is the difference between a
	// two-minute fix and an afternoon.
	for code, want := range map[int]string{
		200: "accepted and stored",
		401: "source-restricted",
		404: "no endpoint matched",
		413: "exceeded the 1 MB ceiling",
		500: "could not store the event",
	} {
		got := simulate.Result{StatusCode: code}.Explain()
		if !contains(got, want) {
			t.Errorf("Explain(%d) = %q, want it to mention %q", code, got, want)
		}
	}
}

func TestSimulatorRefusesAnUnknownProvider(t *testing.T) {
	if _, err := simulate.List("nonesuch"); err == nil {
		t.Fatal("listing samples for an unknown provider succeeded")
	}
	if _, err := simulate.Sign("nonesuch", []byte("{}"), "s", time.Now()); err == nil {
		t.Fatal("signing for an unknown provider succeeded")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
