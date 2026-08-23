// Package tunnel streams a tenant's events to a developer's machine.
//
// It exists to remove the single largest cause of a stalled evaluation: an
// engineer cannot develop against webhooks without a publicly reachable URL,
// so they reach for ngrok, or they hand-craft payloads from the
// documentation, or they give up and test in staging with real money.
//
// The mechanism is deliberately boring. The CLI long-polls for events the
// server has not yet handed it, POSTs each one at localhost, and reports the
// response back so the server knows it was delivered. No inbound connection
// to the laptop, no websocket to keep alive through a hotel network, and
// nothing that behaves differently from the production delivery path — the
// payload is byte-identical to what the customer's real destination receives,
// signed the same way, because the whole point is to develop against the real
// thing.
package tunnel

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// MaxWait is how long a poll blocks before returning empty.
//
// Twenty-five seconds. Long enough that an idle developer's laptop is making
// two requests a minute rather than sixty, and short enough to stay under the
// thirty-second idle timeout that most load balancers and corporate proxies
// impose without telling anybody.
const MaxWait = 25 * time.Second

// MaxSessionAge bounds how long a session survives without polling.
//
// A developer closes their laptop and walks away; without this, the server
// holds their queue forever and keeps diverting events from it.
const MaxSessionAge = 10 * time.Minute

// Delivery is one event handed to a listening developer.
type Delivery struct {
	EventID   string                `json:"event_id"`
	Provider  string                `json:"provider"`
	EventType string                `json:"event_type"`
	Payload   []byte                `json:"payload"`
	Signature string                `json:"signature"`
	Event     domain.CanonicalEvent `json:"-"`
	QueuedAt  time.Time             `json:"queued_at"`
}

// Outcome is what the developer's local handler said.
type Outcome struct {
	EventID    string        `json:"event_id"`
	StatusCode int           `json:"status_code"`
	Duration   time.Duration `json:"duration"`
	Error      string        `json:"error,omitempty"`
}

// Session is one developer listening.
type Session struct {
	ID       string
	TenantID string

	// Filter narrows what is streamed, so an engineer working on refunds is
	// not woken up by every payment.
	Filter domain.Filter

	// Forward is where the CLI is posting locally. Recorded only so the
	// dashboard can show who is listening and to what — the server never
	// connects to it.
	Forward string

	StartedAt time.Time
	LastSeen  time.Time

	// Delivered and Failed are shown in the CLI's running tally, which is the
	// only feedback a developer gets that the thing is working.
	Delivered int64
	Failed    int64

	queue   []Delivery
	waiters []chan struct{}
}

// ErrNoSession is returned for an unknown or expired session.
var ErrNoSession = errors.New("no such listen session")

// Hub holds the active sessions.
//
// In memory, per process, and deliberately not persisted. A listen session is
// a developer's terminal window: if the server restarts, the CLI reconnects
// and starts a new one, and nothing about that is worth surviving a deploy.
type Hub struct {
	mu       sync.Mutex
	sessions map[string]*Session

	// maxQueue bounds one session's backlog. A developer whose local handler
	// is broken must not accumulate an unbounded queue on the server.
	maxQueue int

	// maxWait is how long a poll blocks. Configurable because a deployment
	// behind a proxy with a shorter idle timeout needs a shorter poll, and
	// discovering that as intermittent disconnections is a bad afternoon.
	maxWait time.Duration

	now func() time.Time
}

// Options configure a Hub.
type Options struct {
	MaxQueue int
	MaxWait  time.Duration
	Now      func() time.Time
}

// NewHub builds a Hub.
func NewHub(o Options) *Hub {
	h := &Hub{sessions: map[string]*Session{}, maxQueue: o.MaxQueue, maxWait: o.MaxWait, now: o.Now}
	if h.maxQueue <= 0 {
		h.maxQueue = 100
	}
	if h.maxWait <= 0 {
		h.maxWait = MaxWait
	}
	if h.now == nil {
		h.now = func() time.Time { return time.Now().UTC() }
	}
	return h
}

// Start opens a session.
func (h *Hub) Start(tenantID, forward string, filter domain.Filter) *Session {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := h.now()
	s := &Session{
		ID: domain.NewID("lsn"), TenantID: tenantID, Filter: filter, Forward: forward,
		StartedAt: now, LastSeen: now,
	}
	h.sessions[s.ID] = s
	return s
}

// Stop closes a session.
func (h *Hub) Stop(tenantID, sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.sessions[sessionID]; ok && s.TenantID == tenantID {
		for _, w := range s.waiters {
			close(w)
		}
		delete(h.sessions, sessionID)
	}
}

// Publish offers an event to every matching session.
//
// It returns how many sessions took it. Nothing about this diverts the event
// from its real destinations: a developer listening locally must not stop
// production deliveries, or turning on `listen` in the wrong terminal would
// silently break the customer's live integration.
func (h *Hub) Publish(e domain.CanonicalEvent, payload []byte, signature string) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := h.now()
	var taken int
	for _, s := range h.sessions {
		if s.TenantID != e.TenantID || !s.Filter.Matches(&e) {
			continue
		}
		if now.Sub(s.LastSeen) > MaxSessionAge {
			// The developer closed their laptop. Their queue stops growing
			// rather than being held forever.
			continue
		}
		if len(s.queue) >= h.maxQueue {
			// Oldest dropped rather than newest refused: a developer whose
			// handler was broken ten minutes ago wants the events from the
			// last thirty seconds, not the first hundred from when it broke.
			s.queue = s.queue[1:]
		}
		s.queue = append(s.queue, Delivery{
			EventID: e.ID, Provider: e.Provider, EventType: e.EventType.String(),
			Payload: payload, Signature: signature, Event: e, QueuedAt: now,
		})
		taken++

		for _, w := range s.waiters {
			close(w)
		}
		s.waiters = nil
	}
	return taken
}

// Poll returns queued events, waiting up to MaxWait for one to arrive.
func (h *Hub) Poll(ctx context.Context, tenantID, sessionID string, max int) ([]Delivery, error) {
	if max <= 0 || max > 50 {
		max = 20
	}

	h.mu.Lock()
	s, ok := h.sessions[sessionID]
	if !ok || s.TenantID != tenantID {
		h.mu.Unlock()
		return nil, ErrNoSession
	}
	s.LastSeen = h.now()

	if len(s.queue) > 0 {
		out := s.take(max)
		h.mu.Unlock()
		return out, nil
	}

	wake := make(chan struct{})
	s.waiters = append(s.waiters, wake)
	h.mu.Unlock()

	timer := time.NewTimer(h.maxWait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		// An empty return is the normal case on a quiet endpoint, and the CLI
		// simply polls again. It is not an error and must not be logged as
		// one.
		return nil, nil
	case <-wake:
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok = h.sessions[sessionID]
	if !ok {
		return nil, ErrNoSession
	}
	return s.take(max), nil
}

// take removes and returns up to max queued deliveries. Callers hold h.mu.
func (s *Session) take(max int) []Delivery {
	if len(s.queue) < max {
		max = len(s.queue)
	}
	out := s.queue[:max]
	s.queue = s.queue[max:]
	return out
}

// Report records what the developer's handler said.
//
// It exists so the CLI's tally is the server's tally: a developer reading
// "47 delivered, 2 failed" in their terminal and an operator reading
// something different in the dashboard is a confusing five minutes nobody
// needs.
func (h *Hub) Report(tenantID, sessionID string, outcomes []Outcome) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	s, ok := h.sessions[sessionID]
	if !ok || s.TenantID != tenantID {
		return ErrNoSession
	}
	s.LastSeen = h.now()
	for _, o := range outcomes {
		if o.Error == "" && o.StatusCode >= 200 && o.StatusCode < 300 {
			s.Delivered++
			continue
		}
		s.Failed++
	}
	return nil
}

// Sessions lists a tenant's active sessions, for the dashboard.
func (h *Hub) Sessions(tenantID string) []Session {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := h.now()
	out := make([]Session, 0, len(h.sessions))
	for _, s := range h.sessions {
		if s.TenantID != tenantID || now.Sub(s.LastSeen) > MaxSessionAge {
			continue
		}
		// Copied without the queue and waiters, which are internal and not
		// safe to hand out.
		out = append(out, Session{
			ID: s.ID, TenantID: s.TenantID, Filter: s.Filter, Forward: s.Forward,
			StartedAt: s.StartedAt, LastSeen: s.LastSeen,
			Delivered: s.Delivered, Failed: s.Failed,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.Before(out[j].StartedAt) })
	return out
}

// Sweep forgets sessions nobody is polling.
func (h *Hub) Sweep() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	cutoff := h.now().Add(-MaxSessionAge)
	var removed int
	for id, s := range h.sessions {
		if s.LastSeen.Before(cutoff) {
			for _, w := range s.waiters {
				close(w)
			}
			delete(h.sessions, id)
			removed++
		}
	}
	return removed
}

// Queued is how many events a session is holding, for the CLI to warn a
// developer whose handler has fallen behind.
func (h *Hub) Queued(tenantID, sessionID string) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[sessionID]
	if !ok || s.TenantID != tenantID {
		return 0, ErrNoSession
	}
	return len(s.queue), nil
}
