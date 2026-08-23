// Package nibss adapts NIBSS NIP credit notifications.
//
// Signature: HMAC-SHA256 over a concatenation of named fields, hex — not over
// the raw body. Amounts: major units as a decimal string. Timestamps: naive
// local time, in Africa/Lagos. Response codes: ISO-8583 style, where "00" is
// success and the rest are not.
//
// NIBSS is the reason the Adapter interface takes the raw body rather than a
// parsed document: this scheme has to parse the payload before it can decide
// what to verify, which is a materially weaker construction than signing the
// bytes, and the difference is documented rather than smoothed over.
package nibss

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/jsonpath"
)

// Header is where NIBSS puts the signature.
const Header = "x-nibss-signature"

// Adapter implements adapter.Adapter for NIBSS NIP.
type Adapter struct{}

// New returns the NIBSS adapter.
func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "nibss" }

var (
	pSession   = jsonpath.MustCompile("$.sessionId")
	pPaymentRf = jsonpath.MustCompile("$.paymentReference")
	pAmount    = jsonpath.MustCompile("$.amount")
	pRespCode  = jsonpath.MustCompile("$.responseCode")
	pCurrency  = jsonpath.MustCompile("$.currency")
	pDate      = jsonpath.MustCompile("$.transactionDateTime")
	pOrigAcct  = jsonpath.MustCompile("$.originatorAccountName")
	pNarration = jsonpath.MustCompile("$.narration")
	pChannel   = jsonpath.MustCompile("$.channelCode")
)

// Verify recomputes the digest over sessionId + paymentReference + amount.
//
// The concatenation is the provider's design and it has a real weakness worth
// stating: it covers three fields, so every other field in the payload —
// narration, account names, the response code itself — is unauthenticated. An
// attacker who can reach the endpoint and knows a valid session can alter the
// response code without invalidating the signature.
//
// What contains that: the source-address check below, the unguessable
// receiver token, and deduplication on sessionId. The dashboard states that
// this endpoint is protected by a partial-coverage signature rather than
// presenting all six providers as equally verified.
func (a *Adapter) Verify(headers http.Header, rawBody []byte, secret string) error {
	presented := adapter.FirstHeader(headers, Header, "nibss-signature")
	if presented == "" {
		return adapter.ErrNoSignature
	}

	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return adapter.Failf(adapter.ErrMalformedHeader, "payload is not JSON, so the signed fields cannot be read")
	}

	session, err := jsonpath.StringAt(doc, pSession)
	if err != nil {
		return adapter.Failf(adapter.ErrBadSignature, "payload has no sessionId to sign over")
	}
	ref, err := jsonpath.StringAt(doc, pPaymentRf)
	if err != nil {
		return adapter.Failf(adapter.ErrBadSignature, "payload has no paymentReference to sign over")
	}
	amount, err := jsonpath.StringAt(doc, pAmount)
	if err != nil {
		return adapter.Failf(adapter.ErrBadSignature, "payload has no amount to sign over")
	}

	return adapter.VerifyHMAC(adapter.SHA256, adapter.Hex, secret, []byte(session+ref+amount), presented)
}

// AllowedSources are the ranges NIBSS publishes for NIP notifications.
//
// They are a default, not a rule: a provider adds an egress range without
// announcing it, and waiting for a StatusHub release to accept the new one
// would mean dropped credit notifications. An endpoint's own list overrides
// this (§10).
func (a *Adapter) AllowedSources() []string {
	return []string{
		"196.6.103.0/24",
		"197.253.19.0/24",
		"41.203.72.0/24",
	}
}

// WhySourceCheckIsWeaker is shown verbatim wherever this adapter is used. A
// customer accepting a weaker control should be told, in words, what they are
// accepting.
func (a *Adapter) WhySourceCheckIsWeaker() string {
	return "NIBSS signs three fields rather than the whole payload, so the remaining fields — including " +
		"the response code — are not covered. The source-address check narrows who can reach the " +
		"endpoint, but an address can be spoofed on a network path we do not control, and published " +
		"ranges change without notice. Treat this endpoint as authenticated more weakly than the others."
}

// responseCodes are the NIP codes StatusHub maps.
//
// The rule for everything absent is unknown, and it matters more here than
// anywhere else: NIP has well over a hundred codes, many of them bank
// specific, and several mean "the transfer is still in flight". Mapping an
// unrecognised code to failed would have a fintech reverse a transfer that
// later settles — the exact scenario StatusUnknown exists to prevent.
var responseCodes = map[string]domain.Status{
	"00": domain.StatusSuccess,
	"01": domain.StatusPending, // in progress
	"09": domain.StatusPending, // request in progress
	"25": domain.StatusFailed,  // unable to locate record
	"03": domain.StatusFailed,  // invalid sender
	"05": domain.StatusFailed,  // do not honour
	"06": domain.StatusFailed,  // dormant account
	"07": domain.StatusFailed,  // invalid account
	"08": domain.StatusFailed,  // account name mismatch
	"12": domain.StatusFailed,  // invalid transaction
	"13": domain.StatusFailed,  // invalid amount
	"21": domain.StatusFailed,  // no action taken
	"26": domain.StatusFailed,  // duplicate record
	"34": domain.StatusFailed,  // suspected fraud
	"51": domain.StatusFailed,  // insufficient funds
	"57": domain.StatusFailed,  // transaction not permitted to sender
	"61": domain.StatusFailed,  // transfer limit exceeded
	"91": domain.StatusPending, // beneficiary bank unavailable — retryable, not failed
	"94": domain.StatusFailed,  // duplicate transaction
	"96": domain.StatusPending, // system malfunction — outcome genuinely unknown yet
	"97": domain.StatusPending, // timeout waiting for the beneficiary bank
	"99": domain.StatusFailed,  // general failure
}

// Parse maps a NIP credit notification onto the canonical schema.
func (a *Adapter) Parse(rawBody []byte) (domain.CanonicalEvent, error) {
	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return domain.CanonicalEvent{}, fmt.Errorf("%w: %v", adapter.ErrUnparseable, err)
	}

	ev := domain.CanonicalEvent{
		Provider:        "nibss",
		ProviderExtra:   map[string]any{},
		MappingComplete: true,
	}

	// paymentReference is the originating institution's; sessionId is NIBSS's
	// own and is globally unique. The reference correlates to the fintech's
	// own record, so it is preferred.
	if r, err := jsonpath.StringAt(doc, pPaymentRf); err == nil && r != "" {
		ev.TransactionRef = r
	} else if s, err := jsonpath.StringAt(doc, pSession); err == nil && s != "" {
		ev.TransactionRef = s
		ev.MappingComplete = false
	} else {
		return domain.CanonicalEvent{}, fmt.Errorf("%w: no paymentReference or sessionId", adapter.ErrNoTransaction)
	}

	if s, err := jsonpath.StringAt(doc, pSession); err == nil && s != "" {
		ev.ProviderEventID = s
	}

	code, err := jsonpath.StringAt(doc, pRespCode)
	if err != nil {
		ev.Status = domain.StatusUnknown
		ev.MappingComplete = false
	} else {
		// Codes arrive as "00" and, from some institutions, as the integer 0.
		// Both mean success, and left-padding puts them in the same place.
		key := strings.TrimSpace(code)
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
	// NIP is a transfer rail. Everything on it is a transfer.
	ev.EventType = domain.EventTypeFor("transfer", ev.Status)

	currency := "NGN"
	if c, err := jsonpath.StringAt(doc, pCurrency); err == nil && c != "" {
		currency = domain.NormaliseCurrency(c)
	}
	ev.Currency = currency

	if s, err := jsonpath.StringAt(doc, pAmount); err == nil && s != "" {
		if minor, cerr := domain.MajorToMinor(s, currency); cerr == nil {
			ev.AmountMinor = minor
		} else {
			ev.MappingComplete = false
		}
	} else {
		ev.MappingComplete = false
	}

	if ts, err := jsonpath.StringAt(doc, pDate); err == nil && ts != "" {
		// NIP timestamps carry no zone. Africa/Lagos is stated, never
		// inferred: read as UTC, every credit notification would appear an
		// hour before the debit that caused it.
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

	// The originator's account name is a person's name. It is carried as a
	// value to be hashed with the tenant's salt, never written in the clear
	// (§8.4).
	if name, err := jsonpath.StringAt(doc, pOrigAcct); err == nil && name != "" {
		ev.CustomerRefHash = name
	}

	ev.ProviderExtra = extras(doc)
	return ev, nil
}

var claimed = map[string]struct{}{
	"sessionId":             {},
	"paymentReference":      {},
	"amount":                {},
	"responseCode":          {},
	"currency":              {},
	"transactionDateTime":   {},
	"originatorAccountName": {},
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
	// Narration and channel are the two fields operations staff search on
	// most, so they are named rather than left to a dotted path.
	if s, err := jsonpath.StringAt(doc, pNarration); err == nil {
		out["narration"] = s
	}
	if s, err := jsonpath.StringAt(doc, pChannel); err == nil {
		out["channel_code"] = s
	}
	return out
}

// DedupeKey returns the NIP session ID, which is globally unique and stable
// across redeliveries.
func (a *Adapter) DedupeKey(rawBody []byte) (string, bool) {
	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return "", false
	}
	s, err := jsonpath.StringAt(doc, pSession)
	if err != nil || s == "" {
		return "", false
	}
	return s, true
}

// Describe documents the adapter, including the parts a security review will
// ask about.
func (a *Adapter) Describe() adapter.Description {
	known := make(map[string]string, len(responseCodes))
	for k, v := range responseCodes {
		known[k] = v.String()
	}
	return adapter.Description{
		Name:             "nibss",
		DisplayName:      "NIBSS NIP",
		SignatureScheme:  "HMAC-SHA256 hex over sessionId+paymentReference+amount, plus a source-address check",
		SignatureHeader:  Header,
		KnownStatuses:    known,
		SuppliesEventID:  true,
		SuppliesCurrency: false,
		AmountUnit:       "major",
		Notes: "The signature covers three fields, not the whole payload, so the response code itself is " +
			"unauthenticated. Codes 91, 96 and 97 map to pending rather than failed: the transfer is still " +
			"in flight, and treating it as failed is how a fintech reverses money that later settles. " +
			"Timestamps arrive without a zone and are read as Africa/Lagos.",
	}
}
