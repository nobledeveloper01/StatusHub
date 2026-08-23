// Package paystack adapts Paystack's webhooks.
//
// Signature: HMAC-SHA512 over the raw body, hex, in x-paystack-signature.
// Amounts: minor units already (kobo for NGN), as a JSON number.
// Event ID: none. Paystack sends no stable per-delivery identifier, so
// deduplication falls back to the body hash.
package paystack

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/jsonpath"
)

// Header is where Paystack puts the signature.
const Header = "x-paystack-signature"

// Adapter implements adapter.Adapter for Paystack.
type Adapter struct{}

// New returns the Paystack adapter. It holds no state: secrets arrive per
// call because they are per-endpoint and resolved from the secret manager at
// request time (§10.2).
func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "paystack" }

// Verify checks the HMAC-SHA512 hex digest of the raw body against the
// endpoint's secret key.
//
// Paystack signs with the account's *secret key* rather than a separate
// webhook secret, which means the value in our secret manager is the same
// credential that can move money. It is stored by reference and never
// returned by any API — this is the endpoint whose secret most warrants that.
func (a *Adapter) Verify(headers http.Header, rawBody []byte, secret string) error {
	presented := adapter.FirstHeader(headers, Header)
	if presented == "" {
		return adapter.ErrNoSignature
	}
	if err := adapter.VerifyHMAC(adapter.SHA512, adapter.Hex, secret, rawBody, presented); err != nil {
		return err
	}
	return nil
}

// statusMap is every value Paystack's `data.status` has been observed to
// carry. Anything not listed becomes domain.StatusUnknown and raises the
// unknown-status metric, which is how the next entry in this table gets
// found (§11.2).
var statusMap = map[string]domain.Status{
	"success":    domain.StatusSuccess,
	"successful": domain.StatusSuccess,
	"failed":     domain.StatusFailed,
	"pending":    domain.StatusPending,
	"ongoing":    domain.StatusPending,
	"processing": domain.StatusPending,
	"queued":     domain.StatusPending,
	"abandoned":  domain.StatusAbandoned,
	"reversed":   domain.StatusReversed,
	"reversal":   domain.StatusReversed,
}

// eventFamily maps Paystack's event names onto a canonical family. The
// prefix before the dot is what matters; Paystack's own suffix carries the
// outcome, but `data.status` is more reliable and is what the status mapping
// uses.
func eventFamily(event string) string {
	switch {
	// Disputes are checked first. Paystack names them charge.dispute.create,
	// so a "charge." prefix test placed above this one swallows every
	// chargeback and files it as a payment.
	case strings.Contains(event, "dispute"), strings.Contains(event, "chargeback"):
		return "chargeback"
	case strings.HasPrefix(event, "charge."):
		return "payment"
	case strings.HasPrefix(event, "transfer."):
		return "transfer"
	case strings.HasPrefix(event, "refund."):
		return "refund"
	case strings.HasPrefix(event, "paymentrequest."), strings.HasPrefix(event, "invoice."):
		return "payment"
	case strings.HasPrefix(event, "dispute."):
		return "chargeback"
	default:
		return ""
	}
}

var (
	pEvent     = jsonpath.MustCompile("$.event")
	pRef       = jsonpath.MustCompile("$.data.reference")
	pStatus    = jsonpath.MustCompile("$.data.status")
	pAmount    = jsonpath.MustCompile("$.data.amount")
	pCurrency  = jsonpath.MustCompile("$.data.currency")
	pPaidAt    = jsonpath.MustCompile("$.data.paid_at")
	pCreatedAt = jsonpath.MustCompile("$.data.created_at")
	pCustEmail = jsonpath.MustCompile("$.data.customer.email")
	pCustCode  = jsonpath.MustCompile("$.data.customer.customer_code")
	pTransfer  = jsonpath.MustCompile("$.data.transfer_code")
	pDispute   = jsonpath.MustCompile("$.data.transaction.reference")
)

// Parse maps a Paystack payload onto the canonical schema.
//
// It never returns an error for a field it merely could not find. A missing
// currency or timestamp sets MappingComplete false and lets the event
// through; only a payload with no transaction reference at all is rejected,
// because a reference is what ordering and correlation are keyed on and an
// event without one cannot be delivered in the right sequence.
func (a *Adapter) Parse(rawBody []byte) (domain.CanonicalEvent, error) {
	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return domain.CanonicalEvent{}, fmt.Errorf("%w: %v", adapter.ErrUnparseable, err)
	}

	ev := domain.CanonicalEvent{
		Provider:        "paystack",
		ProviderExtra:   map[string]any{},
		MappingComplete: true,
	}

	eventName, _ := jsonpath.StringAt(doc, pEvent)
	family := eventFamily(eventName)
	if family == "" {
		// An event family we do not recognise is still forwarded — the
		// customer may care about it — but it is flagged so it appears in the
		// mapping-incomplete view rather than looking fully understood.
		family = "payment"
		ev.MappingComplete = false
	}

	ref, err := jsonpath.StringAt(doc, pRef)
	if err != nil || ref == "" {
		// Disputes nest the reference one level deeper, under the disputed
		// transaction. Worth the special case: a chargeback that cannot be
		// correlated to its payment is the one event a fintech most needs
		// correlated.
		if d, derr := jsonpath.StringAt(doc, pDispute); derr == nil && d != "" {
			ref = d
		} else if t, terr := jsonpath.StringAt(doc, pTransfer); terr == nil && t != "" {
			ref = t
		} else {
			return domain.CanonicalEvent{}, fmt.Errorf("%w: no data.reference", adapter.ErrNoTransaction)
		}
	}
	ev.TransactionRef = ref

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

	if v, err := pAmount.Eval(doc); err == nil {
		if n, ok := jsonpath.Int(v); ok {
			// Paystack amounts are already minor units. No conversion, and
			// deliberately no multiplication "just in case" — the most
			// expensive bug available here is a hundredfold error.
			ev.AmountMinor = n
		} else {
			ev.MappingComplete = false
		}
	}
	if c, err := jsonpath.StringAt(doc, pCurrency); err == nil {
		ev.Currency = domain.NormaliseCurrency(c)
	} else if ev.AmountMinor != 0 {
		ev.Currency = "NGN"
		ev.MappingComplete = false
	}

	// paid_at is when the money moved; created_at is when the charge was
	// started. For a completed payment the first is the truth and for a
	// pending one it does not exist yet.
	if ts, err := jsonpath.StringAt(doc, pPaidAt); err == nil && ts != "" && ts != "null" {
		if t, perr := adapter.ParseTime(ts, nil); perr == nil {
			ev.OccurredAt = t
		} else {
			ev.MappingComplete = false
		}
	}
	if ev.OccurredAt.IsZero() {
		if ts, err := jsonpath.StringAt(doc, pCreatedAt); err == nil && ts != "" {
			if t, perr := adapter.ParseTime(ts, nil); perr == nil {
				ev.OccurredAt = t
			} else {
				ev.MappingComplete = false
			}
		}
	}

	if email, err := jsonpath.StringAt(doc, pCustEmail); err == nil && email != "" {
		// Stored on the event only as a value to be hashed later, by the
		// normaliser, with the tenant's own salt. The adapter never sees the
		// salt and never writes an identifier in the clear (§8.4).
		ev.CustomerRefHash = email
	} else if code, err := jsonpath.StringAt(doc, pCustCode); err == nil && code != "" {
		ev.CustomerRefHash = code
	}

	ev.ProviderExtra = extras(doc, eventName)
	return ev, nil
}

// claimed lists the paths Parse consumes. Everything else in the payload goes
// to provider_extra: a field we did not know about today is the field someone
// needs at 2am in six weeks (§3.2 B4).
var claimed = map[string]struct{}{
	"event":                       {},
	"data.reference":              {},
	"data.status":                 {},
	"data.amount":                 {},
	"data.currency":               {},
	"data.paid_at":                {},
	"data.created_at":             {},
	"data.customer.email":         {},
	"data.customer.customer_code": {},
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
		// Kept under its provider-specific name so a customer migrating off
		// their old handler can still switch on Paystack's own event string
		// during the transition.
		out["paystack_event"] = eventName
	}
	return out
}

// DedupeKey reports that Paystack supplies no event identifier.
//
// It genuinely does not: there is no delivery ID, no idempotency header and
// no per-event UUID in the payload. Returning false here is the honest answer
// and sends the caller to body-hash deduplication, which is correct for
// Paystack because it redelivers byte-identical payloads.
func (a *Adapter) DedupeKey(rawBody []byte) (string, bool) { return "", false }

// Describe documents the adapter for the dashboard and the CLI.
func (a *Adapter) Describe() adapter.Description {
	known := make(map[string]string, len(statusMap))
	for k, v := range statusMap {
		known[k] = v.String()
	}
	return adapter.Description{
		Name:             "paystack",
		DisplayName:      "Paystack",
		SignatureScheme:  "HMAC-SHA512 hex over the raw body, using the account secret key",
		SignatureHeader:  Header,
		KnownStatuses:    known,
		SuppliesEventID:  false,
		SuppliesCurrency: true,
		AmountUnit:       "minor",
		Notes: "Paystack sends no per-event identifier, so deduplication uses the body hash. " +
			"Dispute events carry the disputed transaction's reference one level deeper, under data.transaction.reference.",
	}
}
