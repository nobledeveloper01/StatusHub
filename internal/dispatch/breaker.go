package dispatch

import (
	"fmt"
	"sync"
	"time"
)

// BreakerState is a destination's health as the dispatcher sees it.
type BreakerState string

const (
	// BreakerClosed is normal: deliveries proceed.
	BreakerClosed BreakerState = "closed"

	// BreakerOpen means the destination is failing wholesale. Deliveries are
	// parked without consuming their retry budget.
	BreakerOpen BreakerState = "open"

	// BreakerHalfOpen means the cooldown has elapsed and exactly one probe
	// is allowed through to find out whether the destination is back.
	BreakerHalfOpen BreakerState = "half_open"
)

// Breaker tracks per-destination health.
//
// Retries and a breaker solve different problems, and having only retries
// makes the second problem worse. Retries handle one delivery failing against
// a healthy destination. When a destination is down entirely, retries
// multiply load against a service that is trying to come back — every queued
// event, backing off independently, arriving in waves. The breaker notices
// that the failures are not about any particular event and stops sending
// until one probe says otherwise.
//
// The critical property is that an open breaker parks a delivery **without
// consuming an attempt**. Otherwise a thirty-minute outage silently spends
// every queued event's retry budget and dead-letters the lot at the moment
// the customer's service recovers — turning a recoverable outage into a bulk
// replay.
type Breaker struct {
	mu    sync.Mutex
	state map[string]*breakerEntry

	// threshold is consecutive failures before opening. Five, because one or
	// two failures are ordinary and a breaker that trips on them replaces a
	// slightly degraded service with an unavailable one.
	threshold int

	// cooldown is how long an open breaker waits before probing.
	cooldown time.Duration

	// maxCooldown bounds the exponential growth, so a destination that has
	// been down for a day is still probed every few minutes rather than
	// every few hours.
	maxCooldown time.Duration

	now func() time.Time
}

type breakerEntry struct {
	state         BreakerState
	consecutive   int
	openedAt      time.Time
	nextProbeAt   time.Time
	cooldown      time.Duration
	probeInFlight bool

	// lastError is what the dashboard shows beside a tripped breaker. "This
	// destination is unavailable" is not actionable; "connection refused" is.
	lastError string
	trips     int64
}

// BreakerOptions configure a Breaker.
type BreakerOptions struct {
	Threshold   int
	Cooldown    time.Duration
	MaxCooldown time.Duration
	Now         func() time.Time
}

// NewBreaker builds a Breaker.
func NewBreaker(o BreakerOptions) *Breaker {
	b := &Breaker{
		state:       map[string]*breakerEntry{},
		threshold:   o.Threshold,
		cooldown:    o.Cooldown,
		maxCooldown: o.MaxCooldown,
		now:         o.Now,
	}
	if b.threshold <= 0 {
		b.threshold = 5
	}
	if b.cooldown <= 0 {
		b.cooldown = 30 * time.Second
	}
	if b.maxCooldown <= 0 {
		b.maxCooldown = 5 * time.Minute
	}
	if b.now == nil {
		b.now = func() time.Time { return time.Now().UTC() }
	}
	return b
}

// Allow reports whether a delivery to this destination may be attempted, and
// why not when it may not.
//
// A half-open breaker allows exactly one probe at a time. Letting several
// through would mean a destination that is still down takes a burst on every
// cooldown, which is the behaviour the breaker exists to prevent.
func (b *Breaker) Allow(destinationID string) (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	e, ok := b.state[destinationID]
	if !ok || e.state == BreakerClosed {
		return true, ""
	}

	now := b.now()
	if e.state == BreakerOpen {
		if now.Before(e.nextProbeAt) {
			return false, fmt.Sprintf(
				"destination has failed %d times consecutively (%s); next probe in %s",
				e.consecutive, e.lastError, e.nextProbeAt.Sub(now).Round(time.Second))
		}
		e.state = BreakerHalfOpen
		e.probeInFlight = true
		return true, ""
	}

	// Half open: one probe at a time.
	if e.probeInFlight {
		return false, "a probe is already in flight for this destination"
	}
	e.probeInFlight = true
	return true, ""
}

// Succeeded records a successful delivery, closing the breaker.
//
// One success closes it, rather than requiring several. The half-open probe
// is a real delivery carrying a real event, so the destination has already
// demonstrated it can accept one — and holding the breaker open after that
// delays every other event for no additional information.
func (b *Breaker) Succeeded(destinationID string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	e, ok := b.state[destinationID]
	if !ok {
		return
	}
	if e.state != BreakerClosed {
		e.state = BreakerClosed
	}
	e.consecutive = 0
	e.probeInFlight = false
	e.cooldown = 0
	e.lastError = ""
	e.nextProbeAt = time.Time{}
}

// Failed records a failed delivery.
//
// Only transport-level and 5xx failures should reach here. A 400 from a
// destination is about that specific payload, not about the destination's
// health, and counting it would trip the breaker for every other event
// because one of them was malformed.
func (b *Breaker) Failed(destinationID, reason string) BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()

	e, ok := b.state[destinationID]
	if !ok {
		e = &breakerEntry{state: BreakerClosed}
		b.state[destinationID] = e
	}
	now := b.now()
	e.consecutive++
	e.lastError = truncate(reason)
	e.probeInFlight = false

	if e.state == BreakerHalfOpen {
		// The probe failed, so the destination is still down. Back off
		// further rather than probing at the same rate forever.
		e.state = BreakerOpen
		e.cooldown = min(e.cooldown*2, b.maxCooldown)
		if e.cooldown == 0 {
			e.cooldown = b.cooldown
		}
		e.nextProbeAt = now.Add(e.cooldown)
		return e.state
	}

	if e.state == BreakerClosed && e.consecutive >= b.threshold {
		e.state = BreakerOpen
		e.openedAt = now
		e.cooldown = b.cooldown
		e.nextProbeAt = now.Add(e.cooldown)
		e.trips++
	}
	return e.state
}

// State reports a destination's current state, for the dashboard and the
// metric.
func (b *Breaker) State(destinationID string) BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.state[destinationID]; ok {
		return e.state
	}
	return BreakerClosed
}

// Health is what the dashboard renders for one destination.
type Health struct {
	DestinationID       string        `json:"destination_id"`
	State               BreakerState  `json:"state"`
	ConsecutiveFailures int           `json:"consecutive_failures"`
	LastError           string        `json:"last_error,omitempty"`
	OpenedAt            *time.Time    `json:"opened_at,omitempty"`
	NextProbeIn         time.Duration `json:"next_probe_in,omitempty"`
	Trips               int64         `json:"trips"`
}

// Snapshot returns the health of every destination the breaker has seen.
func (b *Breaker) Snapshot() []Health {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	out := make([]Health, 0, len(b.state))
	for id, e := range b.state {
		h := Health{
			DestinationID: id, State: e.state, ConsecutiveFailures: e.consecutive,
			LastError: e.lastError, Trips: e.trips,
		}
		if !e.openedAt.IsZero() {
			t := e.openedAt
			h.OpenedAt = &t
		}
		if e.state == BreakerOpen && e.nextProbeAt.After(now) {
			h.NextProbeIn = e.nextProbeAt.Sub(now).Round(time.Second)
		}
		out = append(out, h)
	}
	return out
}

// Reset closes a breaker manually.
//
// An operator who has just fixed the destination should not have to wait out
// a cooldown that is now measuring nothing. It is a deliberate act, recorded
// in the audit trail by the handler that calls it.
func (b *Breaker) Reset(destinationID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.state, destinationID)
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
