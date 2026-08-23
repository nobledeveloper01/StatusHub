// Package stripe adapts Stripe's webhooks.
//
// Signature: HMAC-SHA256 over "{timestamp}.{raw body}", hex, presented in a
// structured Stripe-Signature header alongside the timestamp it covers.
// Amounts: minor units already.
// Event ID: the top-level id, which is stable across redeliveries.
//
// Stripe's scheme is the strongest of the six, and it is the one StatusHub
// copies for its own outbound signatures (§8.2) — signing a timestamp
// alongside the body is what turns a signature into replay protection rather
// than only integrity.
package stripe

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/jsonpath"
)

// Header carries the timestamp and one or more signatures.
const Header = "stripe-signature"

// Adapter implements adapter.Adapter for Stripe.
type Adapter struct {
	// tolerance bounds how old a signed timestamp may be.
	tolerance time.Duration

	// now is injectable so the window can be tested without sleeping.
	now func() time.Time
}

// New returns the Stripe adapter with the default five-minute window.
func New() *Adapter {
	return &Adapter{tolerance: adapter.DefaultTimestampTolerance, now: time.Now}
}

// WithClock returns a copy using the supplied clock and tolerance. Used by
// the tests, and by a deployment whose provider clock is known to run wide.
func (a *Adapter) WithClock(now func() time.Time, tolerance time.Duration) *Adapter {
	c := *a
	if now != nil {
		c.now = now
	}
	if tolerance > 0 {
		c.tolerance = tolerance
	}
	return &c
}

func (a *Adapter) Name() string { return "stripe" }

// Verify parses the Stripe-Signature header and checks both the digest and
// the timestamp window.
//
// The header can carry several v1 signatures at once — that is how Stripe's
// own endpoint-secret rotation works — and any one of them matching is
// enough. Checking only the first would break rotation for every customer
// who uses it.
func (a *Adapter) Verify(headers http.Header, rawBody []byte, secret string) error {
	presented := adapter.FirstHeader(headers, Header)
	if presented == "" {
		return adapter.ErrNoSignature
	}

	ts, sigs, err := parseHeader(presented)
	if err != nil {
		return err
	}
	if len(sigs) == 0 {
		return adapter.Failf(adapter.ErrMalformedHeader, "header carries a timestamp but no v1 signature")
	}

	// The timestamp is checked before the digest. A captured request replayed
	// hours later carries a genuine signature, so the digest alone would
	// accept it; the window is the part that makes replay fail.
	if err := adapter.CheckTimestamp(ts, a.now(), a.tolerance); err != nil {
		return err
	}

	// The signed payload is the timestamp, a literal dot, then the body. The
	// dot matters: without a separator, a timestamp of 1754903662 with body
	// "x" and a timestamp of 175490366 with body "2x" would sign identically.
	signed := make([]byte, 0, len(rawBody)+16)
	signed = append(signed, strconv.FormatInt(ts.Unix(), 10)...)
	signed = append(signed, '.')
	signed = append(signed, rawBody...)

	expected := adapter.Sign(adapter.SHA256, adapter.Hex, secret, signed)
	for _, s := range sigs {
		if adapter.Equal(s, expected, adapter.Hex) {
			return nil
		}
	}
	return adapter.ErrBadSignature
}

// parseHeader reads `t=1754903662,v1=abc...,v1=def...`, ignoring schemes it
// does not know. Ignoring rather than rejecting is deliberate: Stripe has
// added elements to this header before, and an adapter that refuses an
// unfamiliar one stops working the day they add another.
func parseHeader(h string) (time.Time, []string, error) {
	var (
		ts   time.Time
		sigs []string
	)
	for _, part := range strings.Split(h, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return time.Time{}, nil, adapter.Failf(adapter.ErrMalformedHeader, "timestamp %q is not an integer", v)
			}
			ts = time.Unix(n, 0).UTC()
		case "v1":
			if v != "" {
				sigs = append(sigs, v)
			}
		}
	}
	if ts.IsZero() {
		return time.Time{}, nil, adapter.Failf(adapter.ErrMalformedHeader, "header carries no timestamp")
	}
	return ts, sigs, nil
}

// statusMap covers the status fields Stripe puts on the objects StatusHub
// forwards: payment intents, charges and refunds.
var statusMap = map[string]domain.Status{
	"succeeded":               domain.StatusSuccess,
	"paid":                    domain.StatusSuccess,
	"requires_payment_method": domain.StatusPending,
	"requires_confirmation":   domain.StatusPending,
	"requires_action":         domain.StatusPending,
	"processing":              domain.StatusPending,
	"requires_capture":        domain.StatusPending,
	"pending":                 domain.StatusPending,
	"failed":                  domain.StatusFailed,
	"canceled":                domain.StatusAbandoned,
	"cancelled":               domain.StatusAbandoned,
	"refunded":                domain.StatusReversed,
	"reversed":                domain.StatusReversed,
}

// eventFamily maps Stripe's event names. Stripe's taxonomy is much richer
// than the canonical one, which is the point: a customer switching on
// StatusHub's five families does not have to learn Stripe's two hundred
// event types.
func eventFamily(event string) string {
	e := strings.ToLower(event)
	switch {
	case strings.HasPrefix(e, "charge.dispute"), strings.HasPrefix(e, "issuing_dispute"):
		return "chargeback"
	case strings.HasPrefix(e, "charge.refund"), strings.HasPrefix(e, "refund."):
		return "refund"
	case strings.HasPrefix(e, "payout."), strings.HasPrefix(e, "transfer."):
		return "transfer"
	case strings.HasPrefix(e, "payment_intent."), strings.HasPrefix(e, "charge."),
		strings.HasPrefix(e, "checkout.session."), strings.HasPrefix(e, "invoice."):
		return "payment"
	default:
		return ""
	}
}

var (
	pID       = jsonpath.MustCompile("$.id")
	pType     = jsonpath.MustCompile("$.type")
	pCreated  = jsonpath.MustCompile("$.created")
	pObjID    = jsonpath.MustCompile("$.data.object.id")
	pObjStat  = jsonpath.MustCompile("$.data.object.status")
	pAmount   = jsonpath.MustCompile("$.data.object.amount")
	pReceived = jsonpath.MustCompile("$.data.object.amount_received")
	pCurrency = jsonpath.MustCompile("$.data.object.currency")
	pEmail    = jsonpath.MustCompile("$.data.object.receipt_email")
	pCustomer = jsonpath.MustCompile("$.data.object.customer")
	pMetaRef  = jsonpath.MustCompile("$.data.object.metadata.transaction_ref")
	pRefund   = jsonpath.MustCompile("$.data.object.payment_intent")
	pObjCreat = jsonpath.MustCompile("$.data.object.created")
)

// Parse maps a Stripe event onto the canonical schema.
func (a *Adapter) Parse(rawBody []byte) (domain.CanonicalEvent, error) {
	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return domain.CanonicalEvent{}, fmt.Errorf("%w: %w", adapter.ErrUnparseable, err)
	}

	ev := domain.CanonicalEvent{
		Provider:        "stripe",
		ProviderExtra:   map[string]any{},
		MappingComplete: true,
	}

	if id, err := jsonpath.StringAt(doc, pID); err == nil {
		ev.ProviderEventID = id
	}

	eventName, _ := jsonpath.StringAt(doc, pType)
	family := eventFamily(eventName)
	if family == "" {
		family = "payment"
		ev.MappingComplete = false
	}

	// A fintech's own reference is not something Stripe has a field for, so
	// metadata.transaction_ref is the documented place to put it. Preferring
	// it means ordering and cross-provider correlation work; falling back to
	// Stripe's object ID means they still work within Stripe alone.
	switch {
	case hasString(doc, pMetaRef):
		ev.TransactionRef, _ = jsonpath.StringAt(doc, pMetaRef)
	case family == "refund" && hasString(doc, pRefund):
		// A refund correlates to the payment it reverses, not to itself.
		ev.TransactionRef, _ = jsonpath.StringAt(doc, pRefund)
	case hasString(doc, pObjID):
		ev.TransactionRef, _ = jsonpath.StringAt(doc, pObjID)
	default:
		return domain.CanonicalEvent{}, fmt.Errorf("%w: no data.object.id", adapter.ErrNoTransaction)
	}

	rawStatus, err := jsonpath.StringAt(doc, pObjStat)
	switch {
	case err != nil:
		// Several Stripe objects carry no status at all — a dispute, for
		// instance. The event name is then the only signal, and deriving the
		// status from it is a mapping we are less sure of, so it is flagged.
		ev.Status = statusFromEventName(eventName)
		if ev.Status == domain.StatusUnknown {
			ev.MappingComplete = false
		}
	default:
		if s, ok := statusMap[strings.ToLower(strings.TrimSpace(rawStatus))]; ok {
			ev.Status = s
		} else {
			ev.Status = domain.StatusUnknown
			ev.UnmappedStatus = rawStatus
			ev.MappingComplete = false
		}
	}
	ev.EventType = domain.EventTypeFor(family, ev.Status)

	if c, err := jsonpath.StringAt(doc, pCurrency); err == nil && c != "" {
		ev.Currency = domain.NormaliseCurrency(c)
	}

	// amount_received is what actually settled; amount is what was
	// requested. On a partially-captured intent they differ, and the ledger
	// wants the money that moved.
	amountPath := pAmount
	if hasNumber(doc, pReceived) {
		amountPath = pReceived
	}
	if v, err := amountPath.Eval(doc); err == nil {
		if n, ok := jsonpath.Int(v); ok {
			// Stripe amounts are already minor units, in the currency's own
			// exponent — so a JPY amount of 5000 is 5000 yen, not 50.
			ev.AmountMinor = n
		} else {
			ev.MappingComplete = false
		}
	}

	// The object's own created time is when the money moved; the envelope's
	// is when Stripe built the notification.
	occurred := pObjCreat
	if !hasNumber(doc, pObjCreat) {
		occurred = pCreated
	}
	if v, err := occurred.Eval(doc); err == nil {
		if s, ok := jsonpath.String(v); ok {
			if t, perr := adapter.ParseTime(s, nil); perr == nil {
				ev.OccurredAt = t
			} else {
				ev.MappingComplete = false
			}
		}
	}

	if email, err := jsonpath.StringAt(doc, pEmail); err == nil && email != "" {
		ev.CustomerRefHash = email
	} else if cust, err := jsonpath.StringAt(doc, pCustomer); err == nil && cust != "" {
		ev.CustomerRefHash = cust
	}

	ev.ProviderExtra = extras(doc, eventName)
	return ev, nil
}

// statusFromEventName is the fallback for objects with no status field. It
// reads the outcome from the event name's last segment, which is the only
// information available — and is flagged as a less certain mapping by the
// caller.
func statusFromEventName(event string) domain.Status {
	e := strings.ToLower(event)
	switch {
	case strings.HasSuffix(e, ".succeeded"), strings.HasSuffix(e, ".paid"), strings.HasSuffix(e, ".closed"):
		return domain.StatusSuccess
	case strings.HasSuffix(e, ".failed"), strings.HasSuffix(e, ".payment_failed"):
		return domain.StatusFailed
	case strings.HasSuffix(e, ".created"), strings.HasSuffix(e, ".pending"), strings.HasSuffix(e, ".updated"):
		return domain.StatusPending
	case strings.HasSuffix(e, ".canceled"), strings.HasSuffix(e, ".cancelled"), strings.HasSuffix(e, ".expired"):
		return domain.StatusAbandoned
	case strings.HasSuffix(e, ".refunded"), strings.HasSuffix(e, ".reversed"):
		return domain.StatusReversed
	default:
		return domain.StatusUnknown
	}
}

func hasString(doc any, p jsonpath.Path) bool {
	s, err := jsonpath.StringAt(doc, p)
	return err == nil && s != ""
}

func hasNumber(doc any, p jsonpath.Path) bool {
	v, err := p.Eval(doc)
	if err != nil {
		return false
	}
	_, ok := jsonpath.Int(v)
	return ok
}

var claimed = map[string]struct{}{
	"id":                                   {},
	"type":                                 {},
	"created":                              {},
	"data.object.id":                       {},
	"data.object.status":                   {},
	"data.object.amount":                   {},
	"data.object.amount_received":          {},
	"data.object.currency":                 {},
	"data.object.created":                  {},
	"data.object.receipt_email":            {},
	"data.object.metadata.transaction_ref": {},
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
		out["stripe_event"] = eventName
	}
	return out
}

// DedupeKey returns Stripe's event ID.
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

// Describe documents the adapter.
func (a *Adapter) Describe() adapter.Description {
	known := make(map[string]string, len(statusMap))
	for k, v := range statusMap {
		known[k] = v.String()
	}
	return adapter.Description{
		Name:             "stripe",
		DisplayName:      "Stripe",
		SignatureScheme:  "HMAC-SHA256 hex over \"{timestamp}.{body}\", with a five-minute window",
		SignatureHeader:  Header,
		KnownStatuses:    known,
		SuppliesEventID:  true,
		SuppliesCurrency: true,
		AmountUnit:       "minor",
		Notes: "Put your own reference in metadata.transaction_ref and StatusHub will order and " +
			"correlate on it; without it the Stripe object ID is used, which correlates within " +
			"Stripe but not across providers.",
	}
}
