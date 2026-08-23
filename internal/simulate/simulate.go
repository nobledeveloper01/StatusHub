// Package simulate produces correctly-signed sample webhooks for every
// built-in provider.
//
// It exists because the alternative — waiting for a real transaction to prove
// an integration works — means the first time anybody finds out the receiver
// URL was pasted into the wrong field is when a customer complains about a
// payment that never landed.
//
// The samples are the same corpus the adapter tests run against. That is
// deliberate: a simulator built from separate fixtures drifts, and a
// simulator that sends payloads the adapter would reject is worse than none,
// because it produces a green tick for an integration that does not work.
package simulate

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/flutterwave"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/interswitch"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/monnify"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/nibss"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/paystack"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/stripe"
	"github.com/nobledeveloper01/StatusHub/internal/jsonpath"
)

//go:embed samples/*/*.json
var samples embed.FS

// Sample is one payload a provider might send.
type Sample struct {
	Provider string `json:"provider"`
	Name     string `json:"name"`
	Body     []byte `json:"-"`
}

// Describe renders the sample for a listing.
func (s Sample) Describe() string {
	return fmt.Sprintf("%s/%s (%d bytes)", s.Provider, s.Name, len(s.Body))
}

// List returns every sample, optionally filtered to one provider.
func List(provider string) ([]Sample, error) {
	entries, err := samples.ReadDir("samples")
	if err != nil {
		return nil, err
	}

	var out []Sample
	for _, dir := range entries {
		if !dir.IsDir() {
			continue
		}
		if provider != "" && dir.Name() != provider {
			continue
		}
		files, err := samples.ReadDir(path.Join("samples", dir.Name()))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			body, err := samples.ReadFile(path.Join("samples", dir.Name(), f.Name()))
			if err != nil {
				return nil, err
			}
			out = append(out, Sample{
				Provider: dir.Name(),
				Name:     strings.TrimSuffix(f.Name(), ".json"),
				Body:     body,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].Name < out[j].Name
	})
	if len(out) == 0 {
		return nil, fmt.Errorf("no samples for provider %q", provider)
	}
	return out, nil
}

// Get returns one named sample.
func Get(provider, name string) (Sample, error) {
	all, err := List(provider)
	if err != nil {
		return Sample{}, err
	}
	for _, s := range all {
		if s.Name == name {
			return s, nil
		}
	}
	var names []string
	for _, s := range all {
		names = append(names, s.Name)
	}
	return Sample{}, fmt.Errorf("no sample %q for %s; available: %s", name, provider, strings.Join(names, ", "))
}

// Freshen rewrites the timestamps in a sample to be near now.
//
// Without it, Stripe's window rejects every simulated event as replayed, and
// the operator's first experience of the simulator is a 401 that looks like a
// configuration problem. Rewriting is honest: the sample's *shape* is what is
// being tested, and a stale timestamp only exercises the clock.
func Freshen(s Sample, now time.Time) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(s.Body, &doc); err != nil {
		return s.Body, nil
	}
	rewriteTimes(doc, now, 0)
	out, err := json.Marshal(doc)
	if err != nil {
		return s.Body, nil
	}
	return out, nil
}

// timeFields are the keys providers put timestamps in. Rewriting by key name
// rather than by parsing every string avoids mangling a reference that
// happens to look like a date.
var timeFields = map[string]struct{}{
	"paid_at": {}, "paidat": {}, "created_at": {}, "createdat": {},
	"updated_at": {}, "transactiondatetime": {}, "transactiondate": {},
	"paidon": {}, "created": {}, "timestamp": {}, "date": {},
}

func rewriteTimes(v any, now time.Time, depth int) {
	if depth > 8 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if _, ok := timeFields[strings.ToLower(k)]; ok {
				t[k] = rewriteOne(child, now)
				continue
			}
			rewriteTimes(child, now, depth+1)
		}
	case []any:
		for _, child := range t {
			rewriteTimes(child, now, depth+1)
		}
	}
}

// rewriteOne replaces a timestamp while keeping its original format, because
// the format is exactly what the adapter is being tested against.
func rewriteOne(v any, now time.Time) any {
	switch t := v.(type) {
	case float64:
		return float64(now.Unix())
	case string:
		switch {
		case strings.Contains(t, "T") && strings.HasSuffix(t, "Z"):
			return now.UTC().Format("2006-01-02T15:04:05.000Z")
		case strings.Contains(t, "T"):
			return now.UTC().Format("2006-01-02T15:04:05")
		case strings.Contains(t, "."):
			return now.UTC().Format("2006-01-02 15:04:05.000")
		case strings.Contains(t, ":"):
			return now.UTC().Format("2006-01-02 15:04:05")
		default:
			return t
		}
	default:
		return v
	}
}

// Sign produces the headers a provider would send with this body.
//
// Each branch mirrors that provider's real scheme exactly — including the
// schemes that are weaker than they look. Simulating Flutterwave by
// HMAC-signing the body would produce a request the adapter rejects and teach
// the operator the wrong thing about what that provider actually guarantees.
func Sign(provider string, body []byte, secret string, now time.Time) (map[string]string, error) {
	switch provider {
	case "paystack":
		return map[string]string{
			paystack.Header: adapter.Sign(adapter.SHA512, adapter.Hex, secret, body),
		}, nil

	case "flutterwave":
		// Not a signature: the configured secret hash, echoed verbatim.
		return map[string]string{flutterwave.Header: secret}, nil

	case "monnify":
		return map[string]string{
			monnify.Header: adapter.Sign(adapter.SHA512, adapter.Hex, secret, body),
		}, nil

	case "nibss":
		payload, err := concat(body, "$.sessionId", "$.paymentReference", "$.amount")
		if err != nil {
			return nil, err
		}
		return map[string]string{
			nibss.Header: adapter.Sign(adapter.SHA256, adapter.Hex, secret, payload),
		}, nil

	case "interswitch":
		payload, err := concat(body,
			"$.transaction.transactionRef", "$.transaction.amount", "$.transaction.responseCode")
		if err != nil {
			return nil, err
		}
		return map[string]string{
			interswitch.Header: adapter.Sign(adapter.SHA256, adapter.Base64, secret, payload),
		}, nil

	case "stripe":
		ts := now.UTC().Unix()
		signed := append([]byte(fmt.Sprintf("%d.", ts)), body...)
		return map[string]string{
			stripe.Header: fmt.Sprintf("t=%d,v1=%s", ts,
				adapter.Sign(adapter.SHA256, adapter.Hex, secret, signed)),
		}, nil

	default:
		return nil, fmt.Errorf("no signing scheme known for provider %q", provider)
	}
}

func concat(body []byte, paths ...string) ([]byte, error) {
	doc, err := jsonpath.Decode(body)
	if err != nil {
		return nil, fmt.Errorf("sample is not JSON: %w", err)
	}
	var b strings.Builder
	for _, p := range paths {
		s, err := jsonpath.StringAt(doc, jsonpath.MustCompile(p))
		if err != nil {
			return nil, fmt.Errorf("sample has no %s to sign over: %w", p, err)
		}
		b.WriteString(s)
	}
	return []byte(b.String()), nil
}

// Result is the outcome of one simulated delivery.
type Result struct {
	Provider   string        `json:"provider"`
	Sample     string        `json:"sample"`
	URL        string        `json:"url"`
	StatusCode int           `json:"status_code"`
	Body       string        `json:"body"`
	Duration   time.Duration `json:"duration"`
}

// Explain turns the response into the sentence an operator actually needs.
//
// A bare status code sends people to the source. The three failures that
// matter each have exactly one likely cause, and naming it here is the
// difference between a two-minute fix and an afternoon.
func (r Result) Explain() string {
	switch {
	case r.StatusCode >= 200 && r.StatusCode < 300:
		return "accepted and stored. It will be normalised and forwarded within a second or two."
	case r.StatusCode == 401:
		// Two distinct causes, and an operator needs both named. The second
		// catches everybody the first time they simulate against a NIBSS or
		// other source-restricted endpoint from a laptop, which is not in any
		// provider's published egress range and never will be.
		return "verification failed. Either the secret this simulator signed with is not the one the " +
			"endpoint resolves — check --secret against the endpoint's secret_ref — or the endpoint is " +
			"source-restricted and this machine is not in its allowed ranges. The exact reason is on the " +
			"endpoint's signature-failure view, which is the only place it is ever disclosed."
	case r.StatusCode == 404:
		return "no endpoint matched that URL. Every component is checked: tenant slug, provider, " +
			"environment and token must all match the endpoint the token was issued for."
	case r.StatusCode == 413:
		return "the payload exceeded the 1 MB ceiling."
	case r.StatusCode >= 500:
		return "StatusHub could not store the event. This is the one failure that returns a 5xx, and it " +
			"is deliberate: the provider should retry rather than assume we have it."
	default:
		return "unexpected response."
	}
}

// Send posts a signed sample at a receiver URL.
func Send(ctx context.Context, client *http.Client, url string, s Sample, secret string, now time.Time) (Result, error) {
	body, err := Freshen(s, now)
	if err != nil {
		return Result{}, err
	}
	headers, err := Sign(s.Provider, body, secret, now)
	if err != nil {
		return Result{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	// The real provider's user agent, so a simulated event is indistinguishable
	// from a real one everywhere except the operator's own records — which is
	// the point of a simulation.
	req.Header.Set("User-Agent", "StatusHub-Simulator/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return Result{
		Provider: s.Provider, Sample: s.Name, URL: url,
		StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(respBody)),
		Duration: time.Since(start),
	}, nil
}
