// Package interswitch adapts Interswitch payment notifications.
//
// Signature: HMAC-SHA256 over a concatenation of named fields, base64, in
// x-interswitch-signature. Amounts: minor units, as a string. Response codes:
// ISO-8583 style, "00" being success.
package interswitch

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/jsonpath"
)

// Header is where Interswitch puts the signature.
const Header = "x-interswitch-signature"

// Adapter implements adapter.Adapter for Interswitch.
type Adapter struct{}

// New returns the Interswitch adapter.
func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "interswitch" }

var (
	pTxRef     = jsonpath.MustCompile("$.transaction.transactionRef")
	pPayRef    = jsonpath.MustCompile("$.transaction.paymentReference")
	pAmount    = jsonpath.MustCompile("$.transaction.amount")
	pRespCode  = jsonpath.MustCompile("$.transaction.responseCode")
	pRespDesc  = jsonpath.MustCompile("$.transaction.responseDescription")
	pCurrency  = jsonpath.MustCompile("$.transaction.currencyCode")
	pPaidOn    = jsonpath.MustCompile("$.transaction.transactionDate")
	pCustID    = jsonpath.MustCompile("$.customer.customerId")
	pCustEmail = jsonpath.MustCompile("$.customer.email")
	pRRN       = jsonpath.MustCompile("$.transaction.retrievalReferenceNumber")
	pChannel   = jsonpath.MustCompile("$.transaction.paymentChannel")
)

// Verify recomputes the digest over transactionRef + amount + responseCode.
//
// Unlike NIBSS, the response code is inside the signed set here, which closes
// the "alter the outcome without invalidating the signature" gap. The rest of
// the payload is still uncovered, so the customer email and the channel are
// treated as informational rather than as authenticated facts.
func (a *Adapter) Verify(headers http.Header, rawBody []byte, secret string) error {
	presented := adapter.FirstHeader(headers, Header, "interswitch-signature")
	if presented == "" {
		return adapter.ErrNoSignature
	}

	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return adapter.Failf(adapter.ErrMalformedHeader, "payload is not JSON, so the signed fields cannot be read")
	}

	ref, err := jsonpath.StringAt(doc, pTxRef)
	if err != nil {
		return adapter.Failf(adapter.ErrBadSignature, "payload has no transactionRef to sign over")
	}
	amount, err := jsonpath.StringAt(doc, pAmount)
	if err != nil {
		return adapter.Failf(adapter.ErrBadSignature, "payload has no amount to sign over")
	}
	code, err := jsonpath.StringAt(doc, pRespCode)
	if err != nil {
		return adapter.Failf(adapter.ErrBadSignature, "payload has no responseCode to sign over")
	}

	// Base64 rather than hex, which is Interswitch's choice and the reason
	// the encoding is a parameter of the shared HMAC helpers rather than
	// assumed.
	return adapter.VerifyHMAC(adapter.SHA256, adapter.Base64, secret, []byte(ref+amount+code), presented)
}

// responseCodes maps Interswitch's ISO-8583-style codes. Anything absent is
// unknown, for the same reason as everywhere else: a code we do not recognise
// is not evidence of failure.
var responseCodes = map[string]domain.Status{
	"00": domain.StatusSuccess,
	"09": domain.StatusPending, // in progress
	"10": domain.StatusPending, // partial approval, awaiting completion
	"01": domain.StatusPending,
	"05": domain.StatusFailed, // do not honour
	"06": domain.StatusFailed,
	"12": domain.StatusFailed, // invalid transaction
	"13": domain.StatusFailed, // invalid amount
	"14": domain.StatusFailed, // invalid card number
	"51": domain.StatusFailed, // insufficient funds
	"54": domain.StatusFailed, // expired card
	"55": domain.StatusFailed, // incorrect PIN
	"57": domain.StatusFailed,
	"61": domain.StatusFailed,  // exceeds withdrawal limit
	"91": domain.StatusPending, // issuer unavailable — retryable
	"96": domain.StatusPending, // system malfunction
	"Z1": domain.StatusFailed,  // declined offline
	"Z6": domain.StatusFailed,
	"20": domain.StatusReversed, // reversal processed
}

// Parse maps an Interswitch notification onto the canonical schema.
func (a *Adapter) Parse(rawBody []byte) (domain.CanonicalEvent, error) {
	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return domain.CanonicalEvent{}, fmt.Errorf("%w: %w", adapter.ErrUnparseable, err)
	}

	ev := domain.CanonicalEvent{
		Provider:        "interswitch",
		ProviderExtra:   map[string]any{},
		MappingComplete: true,
	}

	if r, err := jsonpath.StringAt(doc, pPayRef); err == nil && r != "" {
		ev.TransactionRef = r
	} else if r, err := jsonpath.StringAt(doc, pTxRef); err == nil && r != "" {
		ev.TransactionRef = r
	} else {
		return domain.CanonicalEvent{}, fmt.Errorf("%w: no paymentReference or transactionRef", adapter.ErrNoTransaction)
	}

	if r, err := jsonpath.StringAt(doc, pTxRef); err == nil && r != "" {
		ev.ProviderEventID = r
	}

	code, err := jsonpath.StringAt(doc, pRespCode)
	if err != nil {
		ev.Status = domain.StatusUnknown
		ev.MappingComplete = false
	} else {
		key := strings.ToUpper(strings.TrimSpace(code))
		if len(key) == 1 {
			key = "0" + key
		}
		if s, ok := responseCodes[key]; ok {
			ev.Status = s
		} else {
			ev.Status = domain.StatusUnknown
			ev.UnmappedStatus = code
			ev.MappingComplete = false
		}
	}
	ev.EventType = domain.EventTypeFor("payment", ev.Status)

	currency := "NGN"
	if c, err := jsonpath.StringAt(doc, pCurrency); err == nil && c != "" {
		// Interswitch sends the ISO 4217 numeric code — 566 for the naira —
		// rather than the alphabetic one. Passing the digits straight through
		// would put "566" in a CHAR(3) currency column and make every
		// downstream currency comparison fail.
		currency = numericToAlpha(c)
		if currency == "" {
			currency = "NGN"
			ev.MappingComplete = false
		}
	}
	ev.Currency = currency

	if s, err := jsonpath.StringAt(doc, pAmount); err == nil && s != "" {
		// Already minor units.
		if minor, cerr := domain.ParseMinor(s); cerr == nil {
			ev.AmountMinor = minor
		} else {
			ev.MappingComplete = false
		}
	} else {
		ev.MappingComplete = false
	}

	if ts, err := jsonpath.StringAt(doc, pPaidOn); err == nil && ts != "" {
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

	if e, err := jsonpath.StringAt(doc, pCustEmail); err == nil && e != "" {
		ev.CustomerRefHash = e
	} else if id, err := jsonpath.StringAt(doc, pCustID); err == nil && id != "" {
		ev.CustomerRefHash = id
	}

	ev.ProviderExtra = extras(doc)
	return ev, nil
}

// numericToAlpha converts the ISO 4217 numeric codes Interswitch uses.
// Unlisted codes return empty so the caller flags the mapping rather than
// storing digits in a currency field.
var numericCurrencies = map[string]string{
	"566": "NGN", "840": "USD", "978": "EUR", "826": "GBP",
	"936": "GHS", "404": "KES", "710": "ZAR", "800": "UGX",
	"834": "TZS", "952": "XOF", "950": "XAF", "818": "EGP",
}

func numericToAlpha(code string) string {
	c := strings.TrimSpace(code)
	if len(c) == 3 && c[0] >= 'A' && c[0] <= 'Z' {
		return domain.NormaliseCurrency(c)
	}
	if alpha, ok := numericCurrencies[c]; ok {
		return alpha
	}
	// An alphabetic code that is not upper case still resolves; only genuine
	// unknowns fall through.
	if domain.ValidCurrency(c) {
		return domain.NormaliseCurrency(c)
	}
	return ""
}

var claimed = map[string]struct{}{
	"transaction.transactionRef":   {},
	"transaction.paymentReference": {},
	"transaction.amount":           {},
	"transaction.responseCode":     {},
	"transaction.currencyCode":     {},
	"transaction.transactionDate":  {},
	"customer.email":               {},
	"customer.customerId":          {},
}

func extras(doc any) map[string]any {
	flat := jsonpath.Flatten(doc)
	out := make(map[string]any, len(flat))
	for k, v := range flat {
		if _, ok := claimed[k]; ok {
			continue
		}
		out[k] = v
	}
	// The response description is what an operator reads first when a
	// payment failed, and the RRN is what a bank asks for. Both are named.
	if s, err := jsonpath.StringAt(doc, pRespDesc); err == nil {
		out["response_description"] = s
	}
	if s, err := jsonpath.StringAt(doc, pRRN); err == nil {
		out["retrieval_reference_number"] = s
	}
	if s, err := jsonpath.StringAt(doc, pChannel); err == nil {
		out["payment_channel"] = s
	}
	return out
}

// DedupeKey returns Interswitch's own transaction reference.
func (a *Adapter) DedupeKey(rawBody []byte) (string, bool) {
	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return "", false
	}
	r, err := jsonpath.StringAt(doc, pTxRef)
	if err != nil || r == "" {
		return "", false
	}
	return r, true
}

// Describe documents the adapter.
func (a *Adapter) Describe() adapter.Description {
	known := make(map[string]string, len(responseCodes))
	for k, v := range responseCodes {
		known[k] = v.String()
	}
	return adapter.Description{
		Name:             "interswitch",
		DisplayName:      "Interswitch",
		SignatureScheme:  "HMAC-SHA256 base64 over transactionRef+amount+responseCode",
		SignatureHeader:  Header,
		KnownStatuses:    known,
		SuppliesEventID:  true,
		SuppliesCurrency: true,
		AmountUnit:       "minor",
		Notes: "The signature covers the response code, so the transaction outcome cannot be altered " +
			"without invalidating it — but the rest of the payload is uncovered and is treated as " +
			"informational. Currency arrives as the ISO 4217 numeric code and is converted to the " +
			"alphabetic one.",
	}
}
