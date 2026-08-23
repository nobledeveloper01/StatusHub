// Package monnify adapts Monnify's webhooks.
//
// Signature: HMAC-SHA512 over the raw body, hex, in monnify-signature.
// Amounts: major units, as a JSON number.
// Event ID: eventData.transactionReference is stable across redeliveries.
package monnify

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/jsonpath"
)

// Header is where Monnify puts the signature.
const Header = "monnify-signature"

// Adapter implements adapter.Adapter for Monnify.
type Adapter struct{}

// New returns the Monnify adapter.
func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "monnify" }

// Verify checks the HMAC-SHA512 hex digest of the raw body.
func (a *Adapter) Verify(headers http.Header, rawBody []byte, secret string) error {
	presented := adapter.FirstHeader(headers, Header, "x-monnify-signature")
	if presented == "" {
		return adapter.ErrNoSignature
	}
	return adapter.VerifyHMAC(adapter.SHA512, adapter.Hex, secret, rawBody, presented)
}

// statusMap covers eventData.paymentStatus.
//
// PARTIALLY_PAID and OVERPAID are the interesting entries, and they are
// mapped deliberately rather than by omission.
//
// A partial payment is not a success and not a failure. The customer sent
// less than the invoice; the money is real and the obligation is not
// discharged. The canonical enum has no value for that, and both available
// approximations are wrong in a way that costs money: success credits an
// invoice that was not paid, failed discards a payment that was. Mapping it
// to unknown says exactly what is true — StatusHub will not decide this one —
// and the amount is in the event for the customer's own logic to compare
// against what they expected.
//
// OVERPAID goes to success: the obligation is discharged, and the excess is a
// refund question rather than a settlement question. The amount received is
// still reported verbatim, so a handler that cares can see the difference.
var statusMap = map[string]domain.Status{
	"paid":           domain.StatusSuccess,
	"overpaid":       domain.StatusSuccess,
	"partially_paid": domain.StatusUnknown,
	"pending":        domain.StatusPending,
	"processing":     domain.StatusPending,
	"failed":         domain.StatusFailed,
	"cancelled":      domain.StatusAbandoned,
	"expired":        domain.StatusAbandoned,
	"abandoned":      domain.StatusAbandoned,
	"reversed":       domain.StatusReversed,
	"refunded":       domain.StatusReversed,
}

// deliberatelyUnknown lists values that map to unknown on purpose. They must
// not raise the "new unmapped status" alert: an operator paged about
// PARTIALLY_PAID every time one arrives would learn to ignore the alert, and
// then miss the value that genuinely is new.
var deliberatelyUnknown = map[string]string{
	"partially_paid": "the canonical status enum cannot express a part payment; compare amount_minor against your expected amount",
}

func eventFamily(event string) string {
	e := strings.ToUpper(strings.TrimSpace(event))
	switch {
	case strings.Contains(e, "DISBURSEMENT"), strings.Contains(e, "TRANSFER"):
		return "transfer"
	case strings.Contains(e, "REFUND"):
		return "refund"
	case strings.Contains(e, "SETTLEMENT"), strings.Contains(e, "COLLECTION"), strings.Contains(e, "TRANSACTION"):
		return "payment"
	default:
		return ""
	}
}

var (
	pEvent    = jsonpath.MustCompile("$.eventType")
	pTxRef    = jsonpath.MustCompile("$.eventData.transactionReference")
	pPayRef   = jsonpath.MustCompile("$.eventData.paymentReference")
	pStatus   = jsonpath.MustCompile("$.eventData.paymentStatus")
	pAmount   = jsonpath.MustCompile("$.eventData.amountPaid")
	pSettled  = jsonpath.MustCompile("$.eventData.settlementAmount")
	pCurrency = jsonpath.MustCompile("$.eventData.currency")
	pPaidOn   = jsonpath.MustCompile("$.eventData.paidOn")
	pEmail    = jsonpath.MustCompile("$.eventData.customer.email")
)

// Parse maps a Monnify payload onto the canonical schema.
func (a *Adapter) Parse(rawBody []byte) (domain.CanonicalEvent, error) {
	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return domain.CanonicalEvent{}, fmt.Errorf("%w: %v", adapter.ErrUnparseable, err)
	}

	ev := domain.CanonicalEvent{
		Provider:        "monnify",
		ProviderExtra:   map[string]any{},
		MappingComplete: true,
	}

	eventName, _ := jsonpath.StringAt(doc, pEvent)
	family := eventFamily(eventName)
	if family == "" {
		family = "payment"
		ev.MappingComplete = false
	}

	// paymentReference is the merchant's own; transactionReference is
	// Monnify's. The merchant's is preferred for correlation, because it is
	// the identifier the fintech also holds.
	if r, err := jsonpath.StringAt(doc, pPayRef); err == nil && r != "" {
		ev.TransactionRef = r
	} else if r, err := jsonpath.StringAt(doc, pTxRef); err == nil && r != "" {
		ev.TransactionRef = r
	} else {
		return domain.CanonicalEvent{}, fmt.Errorf("%w: no paymentReference or transactionReference", adapter.ErrNoTransaction)
	}

	if id, err := jsonpath.StringAt(doc, pTxRef); err == nil && id != "" {
		ev.ProviderEventID = id
	}

	rawStatus, err := jsonpath.StringAt(doc, pStatus)
	if err != nil {
		ev.Status = domain.StatusUnknown
		ev.MappingComplete = false
	} else {
		key := strings.ToLower(strings.TrimSpace(rawStatus))
		if s, ok := statusMap[key]; ok {
			ev.Status = s
			if why, deliberate := deliberatelyUnknown[key]; deliberate {
				// Understood, not unmapped. The value is recorded as context
				// rather than as a to-do item.
				ev.ProviderExtra["statushub_note"] = why
				ev.ProviderExtra["monnify_payment_status"] = rawStatus
			}
		} else {
			ev.Status = domain.StatusUnknown
			ev.UnmappedStatus = rawStatus
			ev.MappingComplete = false
		}
	}
	ev.EventType = domain.EventTypeFor(family, ev.Status)

	currency := "NGN"
	if c, err := jsonpath.StringAt(doc, pCurrency); err == nil && c != "" {
		currency = domain.NormaliseCurrency(c)
	}
	ev.Currency = currency

	// amountPaid is what actually arrived, which is the number a ledger
	// needs. settlementAmount is what Monnify will pay out after fees, and
	// using it would understate every transaction by the fee.
	amountPath := pAmount
	if _, err := pAmount.Eval(doc); err != nil {
		amountPath = pSettled
		ev.MappingComplete = false
	}
	if v, err := amountPath.Eval(doc); err == nil {
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

	if ts, err := jsonpath.StringAt(doc, pPaidOn); err == nil && ts != "" {
		// Monnify sends paidOn without a zone. Lagos is stated here rather
		// than inferred: read as UTC it would place every Nigerian payment an
		// hour before it happened, which reorders it against every other
		// event on the same transaction.
		loc, lerr := adapter.LoadLocation("Africa/Lagos")
		if lerr != nil {
			loc = nil
		}
		if t, perr := adapter.ParseTime(ts, loc); perr == nil {
			ev.OccurredAt = t
		} else {
			ev.MappingComplete = false
		}
	}

	if email, err := jsonpath.StringAt(doc, pEmail); err == nil && email != "" {
		ev.CustomerRefHash = email
	}

	for k, v := range extras(doc, eventName) {
		if _, taken := ev.ProviderExtra[k]; !taken {
			ev.ProviderExtra[k] = v
		}
	}
	return ev, nil
}

var claimed = map[string]struct{}{
	"eventType":                      {},
	"eventData.transactionReference": {},
	"eventData.paymentReference":     {},
	"eventData.paymentStatus":        {},
	"eventData.amountPaid":           {},
	"eventData.currency":             {},
	"eventData.paidOn":               {},
	"eventData.customer.email":       {},
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
		out["monnify_event"] = eventName
	}
	return out
}

// DedupeKey returns Monnify's own transaction reference.
func (a *Adapter) DedupeKey(rawBody []byte) (string, bool) {
	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return "", false
	}
	id, err := jsonpath.StringAt(doc, pTxRef)
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
		Name:             "monnify",
		DisplayName:      "Monnify",
		SignatureScheme:  "HMAC-SHA512 hex over the raw body",
		SignatureHeader:  Header,
		KnownStatuses:    known,
		SuppliesEventID:  true,
		SuppliesCurrency: true,
		AmountUnit:       "major",
		Notes: "PARTIALLY_PAID maps to unknown on purpose: the canonical enum cannot express a part " +
			"payment, and both approximations cost money. Compare amount_minor against your expected " +
			"amount. Timestamps arrive without a zone and are read as Africa/Lagos.",
	}
}
