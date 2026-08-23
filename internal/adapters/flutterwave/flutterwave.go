// Package flutterwave adapts Flutterwave's webhooks.
//
// Signature: not a signature. Flutterwave sends the tenant's configured
// secret hash verbatim in the verif-hash header, which is a shared secret
// comparison rather than an HMAC over the body. That is a materially weaker
// scheme and it is documented as one below.
// Amounts: major units, as a JSON number.
// Event ID: data.id, an integer that is stable across redeliveries.
package flutterwave

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/jsonpath"
)

// Header carries the secret hash. Flutterwave has spelled it both ways in
// their own documentation, so both are accepted.
const (
	Header    = "verif-hash"
	HeaderAlt = "verify-hash"
)

// Adapter implements adapter.Adapter for Flutterwave.
type Adapter struct{}

// New returns the Flutterwave adapter.
func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "flutterwave" }

// Verify compares the presented secret hash against the configured one, in
// constant time.
//
// This is not a signature and it is worth being precise about why that
// matters. The header does not cover the body, so a valid header taken from
// any past request authenticates any body at all — an attacker who sees one
// genuine webhook can forge every subsequent one. Constant-time comparison
// here protects the secret from being recovered byte by byte; it does not
// make the scheme sound.
//
// What actually contains the risk is everything around it: the secret is
// per-endpoint rather than per-account, the receiver token is unguessable so
// the URL is not enumerable, and deduplication on data.id stops a captured
// request being replayed as a new event. The dashboard states the weaker
// guarantee rather than presenting all six providers as equally verified.
func (a *Adapter) Verify(headers http.Header, rawBody []byte, secret string) error {
	presented := adapter.FirstHeader(headers, Header, HeaderAlt)
	if presented == "" {
		return adapter.ErrNoSignature
	}
	if secret == "" {
		// An endpoint configured with an empty secret would accept any
		// non-empty header, which is worse than having no check at all
		// because it looks like one.
		return adapter.Failf(adapter.ErrBadSignature, "endpoint has no configured secret hash")
	}
	// Encoding is Hex only so that Equal compares decoded bytes where it can;
	// a secret hash that is not hex falls back to a constant-time comparison
	// of the raw text, which is the correct behaviour for an opaque string.
	if !adapter.Equal(presented, secret, adapter.Hex) {
		return adapter.ErrBadSignature
	}
	return nil
}

// statusMap covers data.status across Flutterwave's charge, transfer and
// refund events. The casing varies by event type within one account, which is
// why lookups are lower-cased first.
var statusMap = map[string]domain.Status{
	"successful":     domain.StatusSuccess,
	"success":        domain.StatusSuccess,
	"completed":      domain.StatusSuccess,
	"failed":         domain.StatusFailed,
	"error":          domain.StatusFailed,
	"pending":        domain.StatusPending,
	"new":            domain.StatusPending,
	"processing":     domain.StatusPending,
	"abandoned":      domain.StatusAbandoned,
	"cancelled":      domain.StatusAbandoned,
	"reversed":       domain.StatusReversed,
	"refunded":       domain.StatusReversed,
	"reversal_saved": domain.StatusReversed,
}

func eventFamily(event string) string {
	e := strings.ToLower(event)
	switch {
	case strings.HasPrefix(e, "charge."), e == "charge.completed":
		return "payment"
	case strings.HasPrefix(e, "transfer."):
		return "transfer"
	case strings.HasPrefix(e, "refund."):
		return "refund"
	case strings.Contains(e, "chargeback"), strings.Contains(e, "dispute"):
		return "chargeback"
	default:
		return ""
	}
}

var (
	pEvent    = jsonpath.MustCompile("$.event")
	pEventAlt = jsonpath.MustCompile("$.event.type")
	pID       = jsonpath.MustCompile("$.data.id")
	pTxRef    = jsonpath.MustCompile("$.data.tx_ref")
	pRef      = jsonpath.MustCompile("$.data.reference")
	pFlwRef   = jsonpath.MustCompile("$.data.flw_ref")
	pStatus   = jsonpath.MustCompile("$.data.status")
	pAmount   = jsonpath.MustCompile("$.data.amount")
	pCurrency = jsonpath.MustCompile("$.data.currency")
	pCreated  = jsonpath.MustCompile("$.data.created_at")
	pEmail    = jsonpath.MustCompile("$.data.customer.email")
)

// Parse maps a Flutterwave payload onto the canonical schema.
func (a *Adapter) Parse(rawBody []byte) (domain.CanonicalEvent, error) {
	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return domain.CanonicalEvent{}, fmt.Errorf("%w: %w", adapter.ErrUnparseable, err)
	}

	ev := domain.CanonicalEvent{
		Provider:        "flutterwave",
		ProviderExtra:   map[string]any{},
		MappingComplete: true,
	}

	eventName, err := jsonpath.StringAt(doc, pEvent)
	if err != nil {
		// Some Flutterwave event shapes nest the name under event.type
		// rather than putting a string at event. Both are current.
		eventName, _ = jsonpath.StringAt(doc, pEventAlt)
	}
	family := eventFamily(eventName)
	if family == "" {
		family = "payment"
		ev.MappingComplete = false
	}

	// tx_ref is the merchant's own reference and is what the customer will
	// search on; flw_ref is Flutterwave's. Preferring the merchant's is what
	// makes correlation across providers possible at all — it is the only
	// identifier the fintech also holds.
	if r, err := jsonpath.StringAt(doc, pTxRef); err == nil && r != "" {
		ev.TransactionRef = r
	} else if r, err := jsonpath.StringAt(doc, pRef); err == nil && r != "" {
		ev.TransactionRef = r
	} else if r, err := jsonpath.StringAt(doc, pFlwRef); err == nil && r != "" {
		ev.TransactionRef = r
		ev.MappingComplete = false
	} else {
		return domain.CanonicalEvent{}, fmt.Errorf("%w: no data.tx_ref or data.flw_ref", adapter.ErrNoTransaction)
	}

	if id, err := jsonpath.StringAt(doc, pID); err == nil && id != "" {
		ev.ProviderEventID = id
	}

	rawStatus, err := jsonpath.StringAt(doc, pStatus)
	if err != nil {
		ev.Status = domain.StatusUnknown
		ev.MappingComplete = false
	} else if s, ok := statusMap[strings.ToLower(strings.TrimSpace(rawStatus))]; ok {
		ev.Status = s
	} else {
		ev.Status = domain.StatusUnknown
		ev.UnmappedStatus = rawStatus
		ev.MappingComplete = false
	}
	ev.EventType = domain.EventTypeFor(family, ev.Status)

	currency := "NGN"
	if c, err := jsonpath.StringAt(doc, pCurrency); err == nil && c != "" {
		currency = domain.NormaliseCurrency(c)
	} else {
		ev.MappingComplete = false
	}
	ev.Currency = currency

	// Flutterwave sends major units — 8134.55 means eight thousand naira and
	// fifty-five kobo. The conversion goes through the decimal text rather
	// than a float, because 8134.55 is not representable in binary floating
	// point and multiplying it by 100 gives 813454.999..., which truncates to
	// a kobo less than the customer paid.
	if v, err := pAmount.Eval(doc); err == nil {
		if s, ok := jsonpath.String(v); ok {
			if minor, cerr := domain.MajorToMinor(s, currency); cerr == nil {
				ev.AmountMinor = minor
			} else {
				ev.MappingComplete = false
			}
		} else {
			ev.MappingComplete = false
		}
	}

	if ts, err := jsonpath.StringAt(doc, pCreated); err == nil && ts != "" {
		if t, perr := adapter.ParseTime(ts, nil); perr == nil {
			ev.OccurredAt = t
		} else {
			ev.MappingComplete = false
		}
	}

	if email, err := jsonpath.StringAt(doc, pEmail); err == nil && email != "" {
		ev.CustomerRefHash = email
	}

	ev.ProviderExtra = extras(doc, eventName)
	return ev, nil
}

var claimed = map[string]struct{}{
	"event":               {},
	"event.type":          {},
	"data.id":             {},
	"data.tx_ref":         {},
	"data.reference":      {},
	"data.status":         {},
	"data.amount":         {},
	"data.currency":       {},
	"data.created_at":     {},
	"data.customer.email": {},
}

func extras(doc any, eventName string) map[string]any {
	flat := jsonpath.Flatten(doc)
	out := make(map[string]any, len(flat))
	for k, v := range flat {
		if _, ok := claimed[k]; ok {
			continue
		}
		out[k] = v
	}
	if eventName != "" {
		out["flutterwave_event"] = eventName
	}
	return out
}

// DedupeKey returns data.id, which Flutterwave keeps stable across
// redeliveries of the same event.
func (a *Adapter) DedupeKey(rawBody []byte) (string, bool) {
	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return "", false
	}
	id, err := jsonpath.StringAt(doc, pID)
	if err != nil || id == "" {
		return "", false
	}
	return id, true
}

// Describe documents the adapter, including the part a customer should read
// before choosing to trust it.
func (a *Adapter) Describe() adapter.Description {
	known := make(map[string]string, len(statusMap))
	for k, v := range statusMap {
		known[k] = v.String()
	}
	return adapter.Description{
		Name:             "flutterwave",
		DisplayName:      "Flutterwave",
		SignatureScheme:  "Shared secret hash echoed in a header — not an HMAC over the body",
		SignatureHeader:  Header,
		KnownStatuses:    known,
		SuppliesEventID:  true,
		SuppliesCurrency: true,
		AmountUnit:       "major",
		Notes: "The verif-hash header does not cover the request body, so it cannot detect a modified " +
			"payload the way a signature can. Replay is contained by deduplication on data.id and by the " +
			"unguessable receiver token rather than by the header itself.",
	}
}
