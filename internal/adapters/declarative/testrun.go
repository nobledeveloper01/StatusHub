package declarative

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// TestRequest asks what an adapter would do with a sample payload
// (§7.3, POST /v1/adapters/{name}/test).
type TestRequest struct {
	// Payloads are sample bodies, ideally captured from the real provider.
	Payloads []Sample `json:"payloads"`

	// Secret, when supplied, exercises verification too. Optional, because
	// the common case during authoring is to check the mapping before anyone
	// has been given a signing secret.
	Secret string `json:"secret,omitempty"`
}

// Sample is one payload to test against.
type Sample struct {
	Name    string            `json:"name,omitempty"`
	Body    string            `json:"body"`
	Headers map[string]string `json:"headers,omitempty"`
}

// TestResult reports what the adapter did with the samples.
type TestResult struct {
	Adapter string         `json:"adapter"`
	Valid   bool           `json:"valid"`
	Error   string         `json:"error,omitempty"`
	Samples []SampleResult `json:"samples"`

	// Warnings are things that will not stop the adapter working but will
	// cost the customer later. They are the whole reason this endpoint exists
	// rather than "upload and see": an adapter that parses every sample and
	// still has no event ID mapped is one that will duplicate events on the
	// provider's first retry, and nobody discovers that from a green tick.
	Warnings []string `json:"warnings,omitempty"`
}

// SampleResult is one payload's outcome.
type SampleResult struct {
	Name string `json:"name,omitempty"`

	Parsed   bool   `json:"parsed"`
	Verified *bool  `json:"verified,omitempty"`
	Error    string `json:"error,omitempty"`

	// Event is what the customer's endpoint would have received.
	Event *domain.CanonicalEvent `json:"event,omitempty"`

	// MissingFields names what the mapping did not fill, so an author sees
	// the gap rather than a quietly incomplete event.
	MissingFields []string `json:"missing_fields,omitempty"`

	// UnmappedStatus is the provider value that had no mapping — usually the
	// single most useful line in the whole response.
	UnmappedStatus string `json:"unmapped_status,omitempty"`
}

// Test compiles a configuration and runs it against the samples without
// activating it.
//
// Nothing here touches storage and nothing is registered. An adapter that
// parses badly should be discovered here, against captured payloads, not
// against live traffic — which is also why the runbook for "a provider
// changed their payload" (§11.5) ends by adding the captured samples to the
// adapter's fixtures.
func Test(cfg Config, req TestRequest) TestResult {
	res := TestResult{Adapter: cfg.Name}

	a, err := Compile(cfg)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Valid = true
	res.Warnings = warningsFor(cfg, a)

	for _, s := range req.Payloads {
		res.Samples = append(res.Samples, runSample(a, s, req.Secret))
	}

	// A status value seen in the samples but absent from the mapping table is
	// the most common authoring mistake, and it is worth restating at the top
	// level where it cannot be missed.
	var unmapped []string
	for _, sr := range res.Samples {
		if sr.UnmappedStatus != "" {
			unmapped = append(unmapped, sr.UnmappedStatus)
		}
	}
	if len(unmapped) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"these status values appeared in the samples with no mapping and would become unknown: %s",
			strings.Join(dedupe(unmapped), ", ")))
	}
	return res
}

func runSample(a *Adapter, s Sample, secret string) SampleResult {
	out := SampleResult{Name: s.Name}
	body := []byte(s.Body)

	if secret != "" {
		h := http.Header{}
		for k, v := range s.Headers {
			h.Set(k, v)
		}
		verified := a.Verify(h, body, secret) == nil
		out.Verified = &verified
	}

	ev, err := a.Parse(body)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Parsed = true
	ev.Normalise()
	out.Event = &ev
	out.UnmappedStatus = ev.UnmappedStatus
	out.MissingFields = missingFields(ev)
	return out
}

func missingFields(ev domain.CanonicalEvent) []string {
	var missing []string
	if ev.ProviderEventID == "" {
		missing = append(missing, "provider_event_id")
	}
	if ev.OccurredAt.IsZero() {
		missing = append(missing, "occurred_at")
	}
	if ev.AmountMinor == 0 {
		missing = append(missing, "amount")
	}
	if ev.Currency == "" {
		missing = append(missing, "currency")
	}
	if ev.CustomerRefHash == "" {
		missing = append(missing, "customer_ref")
	}
	return missing
}

// warningsFor names the choices that compile fine and cost the customer
// later.
func warningsFor(cfg Config, a *Adapter) []string {
	var w []string

	if cfg.Mapping.ProviderEventID == "" {
		w = append(w, "no provider_event_id is mapped, so deduplication falls back to hashing the body. "+
			"That is correct for providers that redeliver byte-identical payloads and wrong for any provider "+
			"that varies a timestamp between retries — check before relying on it.")
	}
	if cfg.Mapping.OccurredAt.Path == "" {
		w = append(w, "no occurred_at is mapped, so every event will be timestamped at receipt. "+
			"Ordering within a transaction still holds, but the times shown to your team will be ours, not the provider's.")
	}
	if cfg.Mapping.Amount.Path == "" {
		w = append(w, "no amount is mapped. Events will forward with amount_minor zero.")
	}
	if cfg.Verification.Type == "source_only" {
		w = append(w, a.WhySourceCheckIsWeaker())
	}
	if cfg.Verification.Type == "shared_secret" {
		w = append(w, "a shared-secret header does not cover the request body, so it cannot detect a modified "+
			"payload. Replay is contained by deduplication and by the unguessable receiver token rather than by the header.")
	}
	if cfg.Verification.Type == "hmac" && cfg.Verification.Source == "fields" {
		w = append(w, fmt.Sprintf("the signature covers %d named fields rather than the whole body, so every other "+
			"field is unauthenticated. Confirm the status field is among the signed ones — if it is not, the "+
			"transaction outcome can be altered without invalidating the signature.", len(cfg.Verification.Fields)))
	}
	if cfg.Verification.Type == "hmac" && cfg.Verification.TimestampHeader == "" {
		w = append(w, "no timestamp header is configured, so a captured request stays replayable indefinitely. "+
			"Deduplication limits the damage; a signed timestamp would prevent it.")
	}
	if len(cfg.Mapping.Status.Values) < 2 {
		w = append(w, "the status mapping has fewer than two entries. Every unlisted value becomes unknown, "+
			"which is safe but means most events will forward unclassified.")
	}
	return w
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
