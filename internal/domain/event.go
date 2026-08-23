package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Validation errors. They are distinct values because the receiver, the
// normaliser and the management API each treat them differently: the receiver
// stores an event it cannot understand, the normaliser flags it, and the API
// rejects it.
var (
	ErrNoTenant         = errors.New("event has no tenant")
	ErrNoTransactionRef = errors.New("event has no transaction reference")
	ErrBadStatus        = errors.New("event status is not in the canonical set")
	ErrBadEventType     = errors.New("event type is not in the canonical set")
	ErrBadCurrency      = errors.New("currency is not a three-letter ISO 4217 code")
	ErrNotUTC           = errors.New("timestamp is not UTC")
)

// RawEvent is the provider's bytes, exactly as they arrived, plus what we
// observed about the delivery. It is written before anything tries to
// understand it, and it is the one artefact in the system that cannot be
// regenerated from anywhere else — the provider will not resend.
type RawEvent struct {
	ID         string
	TenantID   string
	EndpointID string
	Provider   string

	// Headers is sanitised at the door: signature and authorisation headers
	// are dropped rather than stored, because a stored signature header plus
	// a stored body is a replay kit for anyone who reaches the database.
	Headers map[string]string

	// Body is verbatim. Not re-marshalled, not pretty-printed, not
	// re-encoded — signature verification is over these exact bytes, and a
	// round trip through a JSON decoder would change them.
	Body       []byte
	BodySHA256 string

	SourceIP       netip.Addr
	SignatureValid bool

	// SignatureError records why verification failed, for the operator's
	// signature-failure view. It is never returned to the caller: telling a
	// forger which part of their signature was wrong turns the endpoint into
	// an oracle (§7.1).
	SignatureError string

	ReceivedAt time.Time
}

// CanonicalEvent is the one shape the customer ever sees (§4.3). Every field
// here has a single stated meaning across all providers, which is the entire
// product.
type CanonicalEvent struct {
	ID              string
	TenantID        string
	RawEventID      string
	Provider        string
	ProviderEventID string

	EventType EventType

	// TransactionRef is the ordering and correlation key. Events sharing one
	// are delivered in sequence (§4.5), so an adapter that leaves it empty
	// gives up ordering for that event — which is why normalisation treats a
	// missing reference as a failure rather than a blank field.
	TransactionRef string

	Status      Status
	AmountMinor int64
	Currency    string

	// CustomerRefHash is a per-tenant salted hash, never the customer's own
	// identifier (§8.4). It is enough to correlate two events as belonging to
	// the same person without StatusHub holding who that person is.
	CustomerRefHash string

	// ProviderExtra carries every field the mapping did not claim. Nothing
	// the provider sent is dropped: a field we did not know about today is
	// the field someone needs to debug something in six weeks.
	ProviderExtra map[string]any

	OccurredAt   time.Time
	ReceivedAt   time.Time
	NormalisedAt time.Time

	// MappingComplete is false when the adapter could not fill a field it
	// expected to, or met a status value it had no mapping for. It drives
	// both the metric and the "what needs an adapter fix" view, and it is
	// deliberately part of the forwarded payload: the customer is told when
	// we are unsure, rather than finding out later.
	MappingComplete bool

	// UnmappedStatus is the provider's own status string when Status came out
	// unknown, so the operator can see exactly what needs mapping.
	UnmappedStatus string
}

// Validate checks the invariants the rest of the system is allowed to assume.
// It is run after normalisation and before persistence, so a broken adapter
// produces a normalisation failure with a named cause rather than a canonical
// row that quietly violates the schema everything downstream trusts.
func (e *CanonicalEvent) Validate() error {
	if e.TenantID == "" {
		return ErrNoTenant
	}
	if e.TransactionRef == "" {
		return ErrNoTransactionRef
	}
	if !e.Status.Valid() {
		return fmt.Errorf("%w: %q", ErrBadStatus, e.Status)
	}
	if !e.EventType.Valid() {
		return fmt.Errorf("%w: %q", ErrBadEventType, e.EventType)
	}
	// An amount is optional — a chargeback notification legitimately has
	// none — but a currency without an amount, or an amount without a
	// currency, means the adapter found half of a pair and should say so.
	if e.AmountMinor != 0 || e.Currency != "" {
		if !ValidCurrency(e.Currency) {
			return fmt.Errorf("%w: %q", ErrBadCurrency, e.Currency)
		}
	}
	if !e.OccurredAt.IsZero() && e.OccurredAt.Location() != time.UTC {
		return fmt.Errorf("%w: occurred_at is %s", ErrNotUTC, e.OccurredAt.Location())
	}
	return nil
}

// Normalise applies the corrections that are always safe, so every adapter
// does not have to remember them. Anything requiring a judgement call is left
// alone and caught by Validate instead.
func (e *CanonicalEvent) Normalise() {
	e.Currency = NormaliseCurrency(e.Currency)
	e.OccurredAt = e.OccurredAt.UTC()
	e.ReceivedAt = e.ReceivedAt.UTC()
	e.NormalisedAt = e.NormalisedAt.UTC()
	if e.ProviderExtra == nil {
		e.ProviderExtra = map[string]any{}
	}
}

// DedupeKey is the identity used to reject a provider redelivering something
// we already hold. The provider's own event ID is preferred; where a provider
// supplies none, the body hash stands in, which is why the raw event's hash
// is computed on the request path rather than lazily.
func (e *CanonicalEvent) DedupeKey(bodySHA256 string) string {
	if e.ProviderEventID != "" {
		return e.Provider + ":" + e.ProviderEventID
	}
	return e.Provider + ":body:" + bodySHA256
}
