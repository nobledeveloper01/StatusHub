package domain

import (
	"hash/fnv"
	"time"
)

// DeliveryStatus is the state of one attempt to hand an event to one
// destination.
type DeliveryStatus string

const (
	DeliveryPending    DeliveryStatus = "pending"
	DeliveryInFlight   DeliveryStatus = "in_flight"
	DeliverySucceeded  DeliveryStatus = "succeeded"
	DeliveryFailed     DeliveryStatus = "failed"      // this attempt failed; more are due
	DeliveryDeadLetter DeliveryStatus = "dead_letter" // retries exhausted, kept for replay
)

// IsTerminal reports whether the dispatcher is finished with this delivery.
func (s DeliveryStatus) IsTerminal() bool {
	return s == DeliverySucceeded || s == DeliveryDeadLetter
}

// Delivery is one event's journey to one destination, including every attempt
// made. Response bodies are kept — truncated — because "their endpoint
// returned 400" is not a diagnosis and "their endpoint returned 400 saying
// unknown currency" is.
type Delivery struct {
	ID            int64
	TenantID      string
	EventID       string
	DestinationID string

	// TransactionRef is denormalised onto the delivery. It is duplicated from
	// the canonical event, and it earns its place: the dispatcher's claim
	// query groups on it to enforce ordering, and joining the events table on
	// every claim would put the largest table in the system on the hot path.
	TransactionRef string

	// Shard is derived from the transaction reference so that every event
	// about one transaction lands on the same queue and is delivered in
	// order (§4.5).
	Shard int

	// Sequence orders deliveries within a transaction reference. Assigned at
	// enqueue time from the event's occurred_at ordering, not at delivery
	// time, so a retry does not overtake an event queued after it.
	Sequence int64

	Attempt      int
	Status       DeliveryStatus
	ResponseCode int
	ResponseBody string
	Error        string
	DurationMS   int

	IsReplay    bool
	NextRetryAt time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// DefaultShards is the shard count for the dispatcher. It is fixed rather
// than derived from the worker count: changing it re-maps transaction
// references onto different shards, and two events about one transaction
// sitting on different shards is exactly the ordering failure the sharding
// exists to prevent. Changing it is a documented migration, not a config
// tweak.
const DefaultShards = 64

// ShardFor picks the queue for a transaction reference (§4.5). Events sharing
// a reference always land together and deliver sequentially; different
// references proceed in parallel.
func ShardFor(transactionRef string, shards int) int {
	if shards <= 0 {
		shards = DefaultShards
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(transactionRef))
	return int(h.Sum32() % uint32(shards))
}

// ShouldRetry decides whether a response code earns another attempt.
//
// The dividing line is whether repeating the request could plausibly work.
// A 5xx or a timeout could. A 400 saying the payload is malformed will say
// the same thing in six hours, and retrying it for nine hours only delays the
// dead-letter that the operator needs to see. 408 and 429 are 4xx that mean
// "later", so they retry; 429 in particular is the destination asking us
// politely, and ignoring it would be rude and counterproductive.
func ShouldRetry(code int) bool {
	switch {
	case code == 0: // transport failure: connection refused, DNS, timeout
		return true
	case code == 408 || code == 429:
		return true
	case code >= 500:
		return true
	default:
		return false
	}
}

// IsSuccess reports whether the destination accepted the event. Any 2xx
// counts. A 3xx does not: following a redirect on a signed POST would replay
// the payload to a location the tenant never registered, which is an SSRF
// primitive handed over willingly.
func IsSuccess(code int) bool { return code >= 200 && code < 300 }

// DeadLetter is a delivery that exhausted its retries, presented with enough
// context for the operator to decide whether to fix and replay or to let it
// go.
type DeadLetter struct {
	Delivery
	Provider       string
	TransactionRef string
	EventType      EventType
	OccurredAt     time.Time
}
