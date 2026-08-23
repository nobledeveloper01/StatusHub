// Package adapter defines what a provider integration has to do, and nothing
// about any particular provider. Provider packages import this; the registry
// in internal/adapters imports them. Keeping the interface here is what stops
// that from being a cycle.
package adapter

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// Verification failures. The receiver distinguishes them for its own logs and
// metrics, and then tells the caller none of it — a 401 with a reason is an
// oracle a forger can tune against (§7.1).
var (
	ErrNoSignature      = errors.New("request carries no signature header")
	ErrBadSignature     = errors.New("signature does not match the body")
	ErrMalformedHeader  = errors.New("signature header is malformed")
	ErrTimestampOutside = errors.New("signature timestamp is outside the accepted window")
	ErrSourceNotAllowed = errors.New("source address is not in the provider's published ranges")
)

// Parsing failures.
var (
	ErrUnparseable    = errors.New("payload is not in the shape this adapter expects")
	ErrNoTransaction  = errors.New("payload carries no transaction reference")
	ErrNoUsableStatus = errors.New("payload carries no status field")
)

// Adapter is one provider's integration (§4.3). Three responsibilities, kept
// separate because they run at different times and fail differently:
// verification happens on the request path and must be fast and
// constant-time, parsing happens afterwards and is allowed to fail without
// costing the event, and deduplication has to work even when parsing does not.
type Adapter interface {
	// Name is the identifier used in the receiver URL and in configuration.
	Name() string

	// Verify authenticates the request against the provider's own scheme,
	// using constant-time comparison. It is handed the raw body, never a
	// re-marshalled one, because the signature covers the exact bytes.
	Verify(headers http.Header, rawBody []byte, secret string) error

	// Parse maps the payload onto the canonical schema. It fills only the
	// fields the provider supplies; the normaliser fills the rest.
	Parse(rawBody []byte) (domain.CanonicalEvent, error)

	// DedupeKey extracts the provider's own event ID where one exists, so a
	// provider retrying an event we already hold does not create a
	// duplicate. Returning false is honest and common — several providers
	// send no stable identifier at all — and the caller falls back to the
	// body hash.
	DedupeKey(rawBody []byte) (string, bool)
}

// SourceRestricted is implemented by adapters for providers that offer no
// signature at all, only a published set of source addresses. It is a
// deliberately awkward interface to implement, because it is a deliberately
// weaker guarantee and should not be reached for by accident (§10).
type SourceRestricted interface {
	Adapter

	// AllowedSources returns the CIDR ranges the provider publishes.
	AllowedSources() []string

	// WhySourceCheckIsWeaker is surfaced verbatim in the dashboard and in
	// the API response when an endpoint uses this adapter. A customer
	// accepting a weaker control should be told, in words, what they are
	// accepting.
	WhySourceCheckIsWeaker() string
}

// Describable lets an adapter document itself for the dashboard's adapter
// list and for `statushubctl adapters describe`, so the answer to "what does
// this one map, and which statuses does it know" lives beside the code that
// does the mapping.
type Describable interface {
	Describe() Description
}

// Description is an adapter's self-documentation.
type Description struct {
	Name             string            `json:"name"`
	DisplayName      string            `json:"display_name"`
	SignatureScheme  string            `json:"signature_scheme"`
	SignatureHeader  string            `json:"signature_header,omitempty"`
	KnownStatuses    map[string]string `json:"known_statuses"`
	SuppliesEventID  bool              `json:"supplies_event_id"`
	SuppliesCurrency bool              `json:"supplies_currency"`
	AmountUnit       string            `json:"amount_unit"`
	Notes            string            `json:"notes,omitempty"`
}

// VerificationError wraps a failure with the detail the operator sees and the
// caller never does.
type VerificationError struct {
	Cause  error
	Detail string
}

func (e *VerificationError) Error() string {
	if e.Detail == "" {
		return e.Cause.Error()
	}
	return fmt.Sprintf("%s: %s", e.Cause, e.Detail)
}

func (e *VerificationError) Unwrap() error { return e.Cause }

// Failf builds a VerificationError. The formatted detail goes to the audit
// trail and the signature-failure view; the wrapped cause is what metrics are
// labelled with.
func Failf(cause error, format string, args ...any) error {
	return &VerificationError{Cause: cause, Detail: fmt.Sprintf(format, args...)}
}
