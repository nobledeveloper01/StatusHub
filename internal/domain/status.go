// Package domain holds the canonical event schema and the vocabulary every
// other package speaks (§4.3). It depends on no storage and no transport, so
// the question "what did the provider actually tell us" can be answered and
// tested without a database.
package domain

import "fmt"

// Status is the normalised outcome of a transaction. It is a closed set. A
// provider value that does not map to one of these becomes StatusUnknown, and
// never a guess.
type Status string

const (
	StatusPending   Status = "pending"
	StatusSuccess   Status = "success"
	StatusFailed    Status = "failed"
	StatusReversed  Status = "reversed"
	StatusAbandoned Status = "abandoned"

	// StatusUnknown is a product decision, not a gap (§4.3).
	//
	// The tempting default for an unrecognised provider status is "failed",
	// because failure is the safe-looking option. It is not: a fintech that
	// treats an unmapped SUCCESS as a failure reverses a payment that
	// actually completed, and the customer is charged for a refund of money
	// they received. Unknown says plainly that StatusHub does not know, which
	// the customer's own code can handle deliberately. It also raises
	// statushub_status_unknown_total{raw_value}, so the unmapped value shows
	// up on a dashboard within a minute instead of in a support ticket.
	StatusUnknown Status = "unknown"
)

var allStatuses = map[Status]struct{}{
	StatusPending:   {},
	StatusSuccess:   {},
	StatusFailed:    {},
	StatusReversed:  {},
	StatusAbandoned: {},
	StatusUnknown:   {},
}

// Valid reports whether s is one of the six. Values read back from storage go
// through here, so a row written by a newer binary fails loudly rather than
// flowing on as free text.
func (s Status) Valid() bool {
	_, ok := allStatuses[s]
	return ok
}

// IsTerminal reports whether the transaction can still change. Only pending
// and unknown can: unknown counts as non-terminal because we do not know what
// it is, and assuming a state we cannot see is finished is the same mistake
// as mapping it to failed.
func (s Status) IsTerminal() bool {
	return s != StatusPending && s != StatusUnknown
}

func (s Status) String() string { return string(s) }

// ParseStatus converts a stored value, rejecting anything unrecognised.
func ParseStatus(v string) (Status, error) {
	s := Status(v)
	if !s.Valid() {
		return "", fmt.Errorf("unrecognised status %q", v)
	}
	return s, nil
}

// EventType is the canonical name for what happened. Providers describe the
// same occurrence with wildly different event names — charge.success,
// transaction.completed, PAYMENT_SUCCESSFUL — and the customer's handler
// should switch on one vocabulary.
type EventType string

const (
	EventPaymentPending   EventType = "payment.pending"
	EventPaymentCompleted EventType = "payment.completed"
	EventPaymentFailed    EventType = "payment.failed"
	EventPaymentReversed  EventType = "payment.reversed"
	EventPaymentAbandoned EventType = "payment.abandoned"

	EventTransferPending   EventType = "transfer.pending"
	EventTransferCompleted EventType = "transfer.completed"
	EventTransferFailed    EventType = "transfer.failed"
	EventTransferReversed  EventType = "transfer.reversed"

	EventRefundCompleted EventType = "refund.completed"
	EventRefundFailed    EventType = "refund.failed"

	EventChargebackOpened   EventType = "chargeback.opened"
	EventChargebackResolved EventType = "chargeback.resolved"

	// EventUnknown pairs with StatusUnknown for the same reason.
	EventUnknown EventType = "unknown"
)

var allEventTypes = map[EventType]struct{}{
	EventPaymentPending:     {},
	EventPaymentCompleted:   {},
	EventPaymentFailed:      {},
	EventPaymentReversed:    {},
	EventPaymentAbandoned:   {},
	EventTransferPending:    {},
	EventTransferCompleted:  {},
	EventTransferFailed:     {},
	EventTransferReversed:   {},
	EventRefundCompleted:    {},
	EventRefundFailed:       {},
	EventChargebackOpened:   {},
	EventChargebackResolved: {},
	EventUnknown:            {},
}

// Valid reports whether t is a recognised canonical event type.
func (t EventType) Valid() bool {
	_, ok := allEventTypes[t]
	return ok
}

func (t EventType) String() string { return string(t) }

// Family is the noun half of the event type — payment, transfer, refund,
// chargeback. Destination filters are usually written against the family
// rather than the exact type.
func (t EventType) Family() string {
	for i := 0; i < len(t); i++ {
		if t[i] == '.' {
			return string(t[:i])
		}
	}
	return string(t)
}

// EventTypeFor composes the canonical event type from a family and a status,
// which is how most adapters derive it: the provider tells us the transaction
// kind and the outcome separately, and this is the only place that pairing
// rule lives.
func EventTypeFor(family string, s Status) EventType {
	// Chargebacks do not have the same lifecycle as a payment. A dispute is
	// opened and later resolved; it is never "completed" and never
	// "abandoned", so mapping its status through the payment vocabulary
	// would produce event types that do not exist.
	if family == "chargeback" {
		switch s {
		case StatusPending:
			return EventChargebackOpened
		case StatusSuccess, StatusFailed, StatusReversed:
			return EventChargebackResolved
		default:
			return EventUnknown
		}
	}

	var suffix string
	switch s {
	case StatusPending:
		suffix = "pending"
	case StatusSuccess:
		suffix = "completed"
	case StatusFailed:
		suffix = "failed"
	case StatusReversed:
		suffix = "reversed"
	case StatusAbandoned:
		suffix = "abandoned"
	default:
		return EventUnknown
	}
	t := EventType(family + "." + suffix)
	if !t.Valid() {
		return EventUnknown
	}
	return t
}
