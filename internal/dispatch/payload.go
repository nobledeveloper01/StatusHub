package dispatch

import (
	"encoding/json"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// Payload is the shape the customer's handler receives (§7.2). It is the
// entire product: one struct, forever, whichever provider sent the event.
//
// The JSON tags are the public contract. Renaming a field here breaks every
// customer's handler at once, which is why schema versioning per destination
// is on the roadmap rather than something to improvise later.
type Payload struct {
	EventID         string `json:"event_id"`
	EventType       string `json:"event_type"`
	Provider        string `json:"provider"`
	ProviderEventID string `json:"provider_event_id,omitempty"`
	TransactionRef  string `json:"transaction_ref"`
	Status          string `json:"status"`

	// AmountMinor is always integer minor units, and Currency is always a
	// three-letter code. A handler never has to ask which unit a provider
	// used, which is the single largest source of bugs in the code this
	// product replaces.
	AmountMinor int64  `json:"amount_minor"`
	Currency    string `json:"currency,omitempty"`

	OccurredAt string `json:"occurred_at"`
	ReceivedAt string `json:"received_at"`

	Customer *CustomerRef `json:"customer,omitempty"`

	// ProviderExtra carries every field the mapping did not claim, so a
	// customer is never blocked waiting for us to add one.
	ProviderExtra map[string]any `json:"provider_extra,omitempty"`

	// MappingComplete tells the customer when StatusHub is unsure. It is part
	// of the payload rather than an internal flag because a handler that
	// treats an incomplete mapping the same as a complete one has been given
	// no way to know the difference.
	MappingComplete bool `json:"mapping_complete"`

	// UnmappedStatus is the provider's own string when Status is "unknown",
	// so a customer can act on a value we cannot classify rather than waiting
	// for us to ship a mapping.
	UnmappedStatus string `json:"unmapped_status,omitempty"`

	// Redacted says the stored original is not byte-exact because card data
	// was removed from it (ADR-002).
	Redacted bool `json:"redacted,omitempty"`

	// Raw is the provider's original body, included only when the
	// destination asked for it. Off by default: most handlers do not want it,
	// and raw bodies are the most sensitive thing StatusHub holds.
	Raw json.RawMessage `json:"raw,omitempty"`
}

// CustomerRef is the pseudonymised customer identity. There is no name, no
// email and no phone number here, and there never will be — the hash is
// enough to correlate two events as belonging to one person without StatusHub
// holding who that person is (§8.4).
type CustomerRef struct {
	RefHash string `json:"ref_hash"`
}

// BuildPayload renders a canonical event for delivery.
func BuildPayload(e domain.CanonicalEvent, raw []byte) Payload {
	p := Payload{
		EventID:         e.ID,
		EventType:       e.EventType.String(),
		Provider:        e.Provider,
		ProviderEventID: e.ProviderEventID,
		TransactionRef:  e.TransactionRef,
		Status:          e.Status.String(),
		AmountMinor:     e.AmountMinor,
		Currency:        e.Currency,
		// RFC 3339 with an explicit Z, always. A timestamp without a zone is
		// how a "success" ends up appearing to precede the "pending" that
		// caused it.
		OccurredAt:      e.OccurredAt.UTC().Format(time.RFC3339Nano),
		ReceivedAt:      e.ReceivedAt.UTC().Format(time.RFC3339Nano),
		ProviderExtra:   e.ProviderExtra,
		MappingComplete: e.MappingComplete,
		UnmappedStatus:  e.UnmappedStatus,
		Redacted:        e.Redacted,
	}
	if e.CustomerRefHash != "" {
		p.Customer = &CustomerRef{RefHash: e.CustomerRefHash}
	}
	if len(raw) > 0 && json.Valid(raw) {
		p.Raw = raw
	}
	return p
}
