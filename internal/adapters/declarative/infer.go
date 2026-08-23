package declarative

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/jsonpath"
)

// Infer proposes an adapter configuration from sample payloads.
//
// Proposed, never activated. Everything here is a guess made from three or
// four examples, and some of the guesses — which field is the amount, whether
// it is major or minor units — are the ones that cost real money when wrong.
// So the output is a draft an engineer reads, edits and tests, and the
// confidence of each guess is stated beside it rather than left for them to
// infer from the fact that we produced something.
//
// What this buys is not correctness, it is the first hour: finding the field
// paths in four nested payloads and building a status table from what
// actually appeared is the tedious part, and it is the part a machine is
// genuinely better at.
func Infer(name string, samples []Sample) (Proposal, error) {
	p := Proposal{Config: Config{Name: name, Version: 1}}
	if len(samples) == 0 {
		return p, fmt.Errorf("inference needs at least one sample payload")
	}

	docs := make([]any, 0, len(samples))
	for i, s := range samples {
		doc, err := jsonpath.Decode([]byte(s.Body))
		if err != nil {
			return p, fmt.Errorf("sample %d is not JSON: %w", i+1, err)
		}
		docs = append(docs, doc)
	}

	// Only fields present in every sample are candidates. A field in one
	// payload out of four is a field that will be absent in production, and
	// mapping it produces an adapter that flags most events incomplete.
	common := commonFields(docs)

	p.Config.Mapping.TransactionRef = pickPath(&p, "transaction_ref", common, refCandidates,
		"the field events are ordered and correlated on. Prefer your own reference over the provider's: "+
			"it is the only identifier you also hold, so it is what makes correlation across providers work.")

	p.Config.Mapping.ProviderEventID = pickPath(&p, "provider_event_id", common, eventIDCandidates,
		"used to recognise a redelivery. Without one, deduplication falls back to hashing the body, "+
			"which is correct only for providers that redeliver byte-identical payloads.")

	statusPath := pickPath(&p, "status", common, statusCandidates,
		"the field carrying the transaction outcome.")
	p.Config.Mapping.Status.Path = statusPath
	p.Config.Mapping.Status.Default = string(domain.StatusUnknown)
	if statusPath != "" {
		p.Config.Mapping.Status.Values, p.StatusesSeen = inferStatuses(docs, statusPath)
		p.Notes = append(p.Notes, fmt.Sprintf(
			"the status table below was built from the %d distinct values that appeared in your samples. "+
				"Any value not listed becomes \"unknown\" rather than being guessed — add the rest before "+
				"you rely on this in production.", len(p.StatusesSeen)))
	}

	p.Config.Mapping.CustomerRef = pickPath(&p, "customer_ref", common, customerCandidates,
		"hashed with your tenant salt before storage; never kept in the clear.")

	if amountPath := pickPath(&p, "amount", common, amountCandidates,
		"the transaction amount."); amountPath != "" {
		p.Config.Mapping.Amount.Path = amountPath
		p.Config.Mapping.Amount.Unit = inferAmountUnit(docs, amountPath, &p)
		p.Config.Mapping.Amount.CurrencyPath = pickPath(&p, "currency", common, currencyCandidates,
			"the ISO 4217 code.")
		if p.Config.Mapping.Amount.CurrencyPath == "" {
			p.Config.Mapping.Amount.DefaultCurrency = "NGN"
			p.Warnings = append(p.Warnings,
				"no currency field was found, so NGN is assumed. Change this if it is wrong: an amount in "+
					"the wrong currency is a hundredfold error waiting to happen in a zero-decimal one.")
		}
	}

	if tsPath := pickPath(&p, "occurred_at", common, timeCandidates,
		"when the money moved, as opposed to when we received the notification."); tsPath != "" {
		p.Config.Mapping.OccurredAt.Path = tsPath
		p.Config.Mapping.OccurredAt.Format, p.Config.Mapping.OccurredAt.Timezone = inferTimeFormat(docs, tsPath, &p)
	}

	// Verification cannot be inferred: nothing in a payload says how it was
	// signed. The block below is a placeholder so the draft loads and its
	// mapping can be tested — an unloadable draft would send the engineer to
	// fix the one thing they were always going to have to look up anyway,
	// before they can check the twenty things we did infer.
	//
	// The header name is obviously derived from the adapter name rather than
	// guessed, so nobody mistakes it for something we found in the payload.
	p.Config.Verification = Verification{
		Type: "hmac", Algorithm: "sha256", Encoding: "hex", Source: "raw_body",
		Header: "x-" + name + "-signature",
	}
	p.Guesses = append(p.Guesses, Guess{
		Field: "verification", Path: p.Config.Verification.Header, Confidence: "none",
		Why: "a payload says nothing about how it was signed, so this is a placeholder derived from the " +
			"adapter name — not something found in your samples.",
	})
	p.Warnings = append(p.Warnings,
		"the verification block is a placeholder, not an inference — a payload says nothing about how it "+
			"was signed. Get the scheme from the provider's documentation and set the header, algorithm and "+
			"encoding before activating this. Until you do, the mapping can be tested but nothing will verify.")

	p.Config.Mapping.EventFamily = "payment"
	return p, nil
}

// Proposal is a draft adapter with the reasoning attached.
type Proposal struct {
	Config Config `json:"config"`

	// Guesses records what each field was inferred from, so an engineer can
	// check the reasoning rather than only the result.
	Guesses []Guess `json:"guesses"`

	StatusesSeen []string `json:"statuses_seen,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

// Guess is one inferred field.
type Guess struct {
	Field string `json:"field"`
	Path  string `json:"path,omitempty"`

	// Confidence is high when the field name is unambiguous, low when it was
	// chosen from several plausible ones, and absent when nothing matched.
	Confidence string `json:"confidence"`
	Why        string `json:"why"`
}

// candidates are field-name fragments, most specific first. Ordering is the
// whole of the heuristic: "tx_ref" is a better transaction reference than
// "reference", which is better than "id".
var (
	refCandidates      = []string{"tx_ref", "txref", "transactionref", "paymentreference", "merchantreference", "reference", "orderid", "txid"}
	eventIDCandidates  = []string{"eventid", "event_id", "notificationid", "sessionid", "id"}
	statusCandidates   = []string{"paymentstatus", "transactionstatus", "responsecode", "status", "state", "result"}
	amountCandidates   = []string{"amountpaid", "amount_paid", "transactionamount", "amount", "value", "total"}
	currencyCandidates = []string{"currencycode", "currency", "ccy"}
	customerCandidates = []string{"customer.email", "email", "payeremail", "accountname", "customerid", "customer.id"}
	timeCandidates     = []string{"paidat", "paid_at", "paidon", "completedat", "transactiondate", "transactiondatetime", "createdat", "created_at", "created", "timestamp", "date"}
)

// commonFields returns dotted paths present in every sample, with the values
// seen at each.
func commonFields(docs []any) map[string][]any {
	if len(docs) == 0 {
		return nil
	}
	first := jsonpath.Flatten(docs[0])
	out := make(map[string][]any, len(first))
	for k, v := range first {
		out[k] = []any{v}
	}
	for _, doc := range docs[1:] {
		flat := jsonpath.Flatten(doc)
		for k := range out {
			v, ok := flat[k]
			if !ok {
				delete(out, k)
				continue
			}
			out[k] = append(out[k], v)
		}
	}
	return out
}

// pickPath chooses the best-matching field and records the reasoning.
func pickPath(p *Proposal, field string, common map[string][]any, candidates []string, why string) string {
	type match struct {
		path string
		rank int
	}
	var matches []match

	for path := range common {
		normalised := strings.ToLower(strings.ReplaceAll(path, "_", ""))
		for rank, c := range candidates {
			if strings.HasSuffix(normalised, strings.ReplaceAll(c, "_", "")) {
				matches = append(matches, match{path: path, rank: rank})
				break
			}
		}
	}
	if len(matches) == 0 {
		p.Guesses = append(p.Guesses, Guess{
			Field: field, Confidence: "none",
			Why: "no field in the samples matched any name this usually goes by. " + why,
		})
		return ""
	}

	// Best-ranked candidate first, then the shallowest path — a top-level
	// `reference` is more likely the transaction reference than one nested
	// four levels inside an unrelated object.
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].rank != matches[j].rank {
			return matches[i].rank < matches[j].rank
		}
		di, dj := strings.Count(matches[i].path, "."), strings.Count(matches[j].path, ".")
		if di != dj {
			return di < dj
		}
		return matches[i].path < matches[j].path
	})

	confidence := "high"
	if len(matches) > 1 {
		// Several plausible fields means the guess is a coin-flip dressed as
		// a decision, and an engineer needs to know which.
		confidence = "low"
		others := make([]string, 0, len(matches)-1)
		for _, m := range matches[1:] {
			others = append(others, "$."+m.path)
		}
		why += " Other candidates: " + strings.Join(others, ", ") + "."
	}

	p.Guesses = append(p.Guesses, Guess{
		Field: field, Path: "$." + matches[0].path, Confidence: confidence, Why: why,
	})
	return "$." + matches[0].path
}

// inferStatuses builds a mapping table from the values that actually appeared.
func inferStatuses(docs []any, path string) (map[string]string, []string) {
	compiled, err := jsonpath.Compile(path)
	if err != nil {
		return nil, nil
	}

	seen := map[string]struct{}{}
	for _, doc := range docs {
		if s, err := jsonpath.StringAt(doc, compiled); err == nil && s != "" {
			seen[s] = struct{}{}
		}
	}

	values := make([]string, 0, len(seen))
	for s := range seen {
		values = append(values, s)
	}
	sort.Strings(values)

	table := make(map[string]string, len(values))
	for _, raw := range values {
		table[raw] = string(guessStatus(raw))
	}
	return table, values
}

// guessStatus maps a raw value onto a canonical status by its wording.
//
// Every guess here is reviewed before activation, which is what makes the
// guessing acceptable at all — and even so, anything ambiguous comes out as
// unknown rather than as a plausible-looking wrong answer.
func guessStatus(raw string) domain.Status {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case v == "00" || v == "0":
		// The ISO-8583 convention, and near-universal on Nigerian rails.
		return domain.StatusSuccess
	case strings.Contains(v, "success"), strings.Contains(v, "complet"),
		strings.Contains(v, "paid"), strings.Contains(v, "approved"), v == "true":
		return domain.StatusSuccess
	case strings.Contains(v, "revers"), strings.Contains(v, "refund"):
		return domain.StatusReversed
	case strings.Contains(v, "pend"), strings.Contains(v, "progress"),
		strings.Contains(v, "process"), strings.Contains(v, "await"), strings.Contains(v, "queue"):
		return domain.StatusPending
	case strings.Contains(v, "cancel"), strings.Contains(v, "abandon"), strings.Contains(v, "expire"):
		return domain.StatusAbandoned
	case strings.Contains(v, "fail"), strings.Contains(v, "declin"),
		strings.Contains(v, "error"), strings.Contains(v, "reject"), v == "false":
		return domain.StatusFailed
	default:
		// Including numeric response codes other than 00: they mean something
		// specific per provider, and inventing a meaning for one is how a
		// fintech reverses a payment that succeeded.
		return domain.StatusUnknown
	}
}

// inferAmountUnit guesses major or minor from the values' shape.
func inferAmountUnit(docs []any, path string, p *Proposal) string {
	compiled, err := jsonpath.Compile(path)
	if err != nil {
		return "minor"
	}

	var (
		anyFractional bool
		values        []string
	)
	for _, doc := range docs {
		v, err := compiled.Eval(doc)
		if err != nil {
			continue
		}
		s, ok := jsonpath.String(v)
		if !ok {
			continue
		}
		values = append(values, s)
		if strings.Contains(s, ".") && strings.Trim(strings.SplitN(s, ".", 2)[1], "0") != "" {
			anyFractional = true
		}
	}

	if anyFractional {
		// A fractional part means the provider is sending naira and kobo, not
		// kobo. This is the one signal here that is close to conclusive.
		p.Guesses = append(p.Guesses, Guess{
			Field: "amount.unit", Path: "major", Confidence: "high",
			Why: "at least one sample amount has a non-zero fractional part (" +
				strings.Join(values, ", ") + "), which only makes sense in major units.",
		})
		return "major"
	}

	// Whole numbers are genuinely ambiguous: 5000 could be fifty naira in
	// kobo or five thousand naira. Saying so is more useful than picking.
	p.Guesses = append(p.Guesses, Guess{
		Field: "amount.unit", Path: "minor", Confidence: "low",
		Why: "every sample amount is a whole number (" + strings.Join(values, ", ") +
			"), which is ambiguous — 5000 is either fifty naira in kobo or five thousand naira. " +
			"Minor is assumed because it is the more common convention. CHECK THIS AGAINST THE " +
			"PROVIDER'S DOCUMENTATION: getting it wrong is a hundredfold error in your ledger.",
	})
	return "minor"
}

// inferTimeFormat recognises the layout and says whether a zone is needed.
func inferTimeFormat(docs []any, path string, p *Proposal) (format, timezone string) {
	compiled, err := jsonpath.Compile(path)
	if err != nil {
		return "", ""
	}

	var sample string
	for _, doc := range docs {
		if s, err := jsonpath.StringAt(doc, compiled); err == nil && s != "" {
			sample = s
			break
		}
	}
	if sample == "" {
		return "", ""
	}

	// A layout that carries its own offset needs no configured zone; the
	// zone-free ones do, and the validator refuses them without it.
	for _, candidate := range []struct{ layout, name string }{
		{time.RFC3339Nano, "RFC 3339 with an offset"},
		{time.RFC3339, "RFC 3339 with an offset"},
		{"2006-01-02T15:04:05.000Z", "ISO 8601 with an explicit Z"},
		{"2006-01-02T15:04:05Z", "ISO 8601 with an explicit Z"},
	} {
		if _, err := time.Parse(candidate.layout, sample); err == nil {
			p.Guesses = append(p.Guesses, Guess{
				Field: "occurred_at.format", Path: candidate.layout, Confidence: "high",
				Why: "the sample \"" + sample + "\" is " + candidate.name + ", so it carries its own zone.",
			})
			return candidate.layout, ""
		}
	}

	for _, layout := range []string{
		"2006-01-02T15:04:05.000", "2006-01-02T15:04:05",
		"2006-01-02 15:04:05.000", "2006-01-02 15:04:05", "2006-01-02",
	} {
		if _, err := time.Parse(layout, sample); err == nil {
			p.Guesses = append(p.Guesses, Guess{
				Field: "occurred_at.format", Path: layout, Confidence: "high",
				Why: "the sample \"" + sample + "\" carries no timezone. Africa/Lagos is proposed because " +
					"it is the common case for this market — CHANGE IT IF WRONG. Read in the wrong zone, " +
					"every event lands an hour from where it belongs and reorders against the rest of its " +
					"transaction.",
			})
			return layout, "Africa/Lagos"
		}
	}

	if _, err := strconv.ParseInt(sample, 10, 64); err == nil {
		p.Guesses = append(p.Guesses, Guess{
			Field: "occurred_at.format", Confidence: "high",
			Why: "the sample \"" + sample + "\" is a Unix timestamp, which is unambiguous. No format needed.",
		})
		return "", ""
	}

	p.Warnings = append(p.Warnings,
		"the timestamp \""+sample+"\" is in a format we do not recognise. Set occurred_at.format by hand.")
	return "", ""
}

// Validate runs the same validation an upload would, so an engineer sees
// immediately whether the draft is even loadable.
func (p Proposal) Validate() error {
	// Compile validates on the way in, so calling both would report the same
	// problem twice in one sentence.
	_, err := Compile(p.Config)
	return err
}

// Summary is the sentence an engineer reads first.
func (p Proposal) Summary() string {
	var high, low, none int
	for _, g := range p.Guesses {
		switch g.Confidence {
		case "high":
			high++
		case "low":
			low++
		default:
			none++
		}
	}
	s := fmt.Sprintf("%d fields inferred with confidence, %d that need checking, %d not found.",
		high, low, none)
	if err := p.Validate(); err != nil {
		return s + " This draft does not yet load: " + err.Error()
	}
	return s + " The draft loads; test it against captured payloads before activating it."
}
