// Package dispatch forwards canonical events to the customer's endpoints.
//
// It is a separate workload from the receiver, deployed separately, and the
// separation is load-bearing: if the dispatcher is entirely down the receiver
// keeps accepting and persisting provider events, and delivery catches up
// afterwards (§11.1). Nothing in here may ever become a dependency of the
// receiver's readiness.
package dispatch

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/metrics"
	"github.com/nobledeveloper01/StatusHub/internal/secret"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

// MaxOutageParking bounds how long a delivery may be parked behind an open
// circuit breaker before it dead-letters anyway.
//
// Twenty-four hours. Long enough that a destination-wide outage — including
// one that starts on a Friday evening — resolves without anybody having to
// replay by hand, and short enough that a destination which has been
// decommissioned without telling us produces visible dead letters within a
// day rather than an ever-growing parked queue nobody is looking at.
const MaxOutageParking = 24 * time.Hour

// maxResponseBody is how much of a destination's response is kept.
//
// One kilobyte. "Their endpoint returned 400" is not a diagnosis; "their
// endpoint returned 400 saying unknown currency" is. Beyond a kilobyte it is
// a stack trace, and storing a customer's stack traces at delivery volume is
// a storage bill and a data-protection question rather than a debugging aid.
const maxResponseBody = 1024

// Listener is offered a copy of every delivered payload, for developers
// listening locally. It is offered a copy and never given the original: a
// developer running `listen` in the wrong terminal must not divert a
// customer's production traffic.
type Listener interface {
	Publish(e domain.CanonicalEvent, payload []byte, signature string) int
}

// Dispatcher delivers events.
type Dispatcher struct {
	store    store.Store
	secrets  secret.Resolver
	metrics  *metrics.Registry
	log      *slog.Logger
	client   *http.Client
	guard    *Guard
	breaker  *Breaker
	listener Listener
	shards   int
	now      func() time.Time
}

// Options configure a Dispatcher.
type Options struct {
	Store    store.Store
	Secrets  secret.Resolver
	Metrics  *metrics.Registry
	Logger   *slog.Logger
	Guard    *Guard
	Breaker  *Breaker
	Listener Listener
	Shards   int
	Now      func() time.Time

	// Client overrides the HTTP client. Supplied by tests; in production the
	// client is built here so the SSRF guard's dialler cannot be left off by
	// accident.
	Client *http.Client
}

// New builds a Dispatcher.
func New(o Options) (*Dispatcher, error) {
	d := &Dispatcher{
		store:    o.Store,
		secrets:  o.Secrets,
		metrics:  o.Metrics,
		log:      o.Logger,
		guard:    o.Guard,
		breaker:  o.Breaker,
		listener: o.Listener,
		shards:   o.Shards,
		now:      o.Now,
		client:   o.Client,
	}
	if d.log == nil {
		d.log = slog.Default()
	}
	if d.metrics == nil {
		d.metrics = metrics.New()
	}
	if d.shards <= 0 {
		d.shards = domain.DefaultShards
	}
	if d.now == nil {
		d.now = func() time.Time { return time.Now().UTC() }
	}
	if d.guard == nil {
		g, err := NewGuard(GuardOptions{})
		if err != nil {
			return nil, err
		}
		d.guard = g
	}
	if d.breaker == nil {
		d.breaker = NewBreaker(BreakerOptions{Now: d.now})
	}
	if d.client == nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
		d.client = &http.Client{
			Transport: &http.Transport{
				// The guard's dialler re-resolves and re-checks the address
				// the connection is about to use, which is the only version
				// of this check that a rebinding attack cannot race.
				DialContext:         d.guard.DialContext(dialer),
				MaxIdleConns:        200,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 5 * time.Second,
				ForceAttemptHTTP2:   true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// Following a redirect on a signed POST would replay the
				// payload to a location the tenant never registered and the
				// guard never checked. That is an SSRF primitive handed over
				// willingly.
				return http.ErrUseLastResponse
			},
		}
	}
	return d, nil
}

// Enqueue implements normalise.Enqueuer: it creates one delivery per matching
// destination.
//
// Sequence numbers are allocated here, at enqueue time, rather than at
// delivery. That is what makes ordering hold under retry: a delivery that
// fails and is retried keeps the sequence it was given, so an event queued
// after it cannot overtake it while it waits (§4.5).
func (d *Dispatcher) Enqueue(ctx context.Context, e domain.CanonicalEvent) error {
	destinations, err := d.store.ListDestinations(ctx, e.TenantID)
	if err != nil {
		return fmt.Errorf("listing destinations: %w", err)
	}

	seq, err := d.store.NextSequence(ctx, e.TenantID, e.TransactionRef)
	if err != nil {
		return fmt.Errorf("allocating a sequence for %s: %w", e.TransactionRef, err)
	}
	shard := domain.ShardFor(e.TransactionRef, d.shards)

	var queued int
	for _, dest := range destinations {
		if !dest.Enabled || !dest.Filter.Matches(&e) {
			continue
		}
		_, err := d.store.EnqueueDelivery(ctx, domain.Delivery{
			TenantID:      e.TenantID,
			EventID:       e.ID,
			DestinationID: dest.ID,
			Shard:         shard,
			Sequence:      seq,
			Status:        domain.DeliveryPending,
			CreatedAt:     d.now(),
		})
		if err != nil {
			return fmt.Errorf("queueing delivery to %s: %w", dest.ID, err)
		}
		queued++
	}

	if queued == 0 {
		// Not an error. A tenant with no destinations yet, or filters that
		// exclude this event, is a normal configuration — and the event is
		// stored and searchable regardless.
		d.log.DebugContext(ctx, "event matched no destination",
			"event", e.ID, "tenant", e.TenantID, "provider", e.Provider)
	}
	return nil
}

// EnqueueReplay creates a delivery for an event that has already been
// delivered once, flagged so the customer can tell the difference (§3.2 C3).
func (d *Dispatcher) EnqueueReplay(ctx context.Context, e domain.CanonicalEvent, destinationID string) (int64, error) {
	dest, err := d.store.GetDestination(ctx, e.TenantID, destinationID)
	if err != nil {
		return 0, err
	}
	seq, err := d.store.NextSequence(ctx, e.TenantID, e.TransactionRef)
	if err != nil {
		return 0, err
	}
	id, err := d.store.EnqueueDelivery(ctx, domain.Delivery{
		TenantID:      e.TenantID,
		EventID:       e.ID,
		DestinationID: dest.ID,
		Shard:         domain.ShardFor(e.TransactionRef, d.shards),
		Sequence:      seq,
		Status:        domain.DeliveryPending,
		IsReplay:      true,
		CreatedAt:     d.now(),
	})
	if err != nil {
		return 0, err
	}
	d.metrics.Inc("statushub_replay_total", metrics.Labels{"tenant": e.TenantID})
	d.audit(ctx, domain.AuditRecord{
		TenantID:  e.TenantID,
		EventType: domain.AuditEventReplayed,
		Actor:     domain.Actor{Type: domain.ActorSystem},
		Subject:   domain.Subject{Type: "event", ID: e.ID},
		Payload:   map[string]any{"destination": dest.ID, "delivery": id},
	})
	return id, nil
}

// DeliverOnce attempts one delivery and records the outcome. It is the whole
// of the delivery logic; the worker loop below only decides when to call it.
func (d *Dispatcher) DeliverOnce(ctx context.Context, del domain.Delivery) error {
	start := d.now()

	event, err := d.store.GetCanonicalEvent(ctx, del.TenantID, del.EventID)
	if err != nil {
		return d.fail(ctx, del, 0, "", fmt.Sprintf("event not found: %v", err), start, false)
	}
	dest, err := d.store.GetDestination(ctx, del.TenantID, del.DestinationID)
	if err != nil {
		return d.fail(ctx, del, 0, "", fmt.Sprintf("destination not found: %v", err), start, false)
	}

	// The breaker check happens after the destination is loaded and before
	// anything is sent. A parked delivery costs no attempt: see park.
	if allowed, why := d.breaker.Allow(dest.ID); !allowed {
		return d.park(ctx, del, dest, why)
	}

	var raw []byte
	if dest.IncludeRaw {
		if r, err := d.store.GetRawEvent(ctx, del.TenantID, event.RawEventID); err == nil {
			raw = r.Body
		}
	}

	schema := ResolveSchema(SchemaVersion(dest.SchemaVersion))
	body, err := RenderPayload(schema, event, raw)
	if err != nil {
		// Unmarshalable content is permanent, so it dead-letters immediately
		// rather than burning nine hours of retries on something that cannot
		// change.
		return d.fail(ctx, del, 0, "", fmt.Sprintf("payload could not be encoded: %v", err), start, false)
	}

	secrets, err := d.secrets.ResolveAll(ctx, dest.SigningSecretRef)
	if err != nil {
		// Transient: a secret manager outage must not consume the retry
		// budget, or an hour of unavailability dead-letters everything.
		return d.retry(ctx, del, dest, 0, "", fmt.Sprintf("signing secret did not resolve: %v", err), start)
	}

	policy := dest.RetryPolicy
	if len(policy.Backoff) == 0 {
		policy = domain.DefaultRetryPolicy()
	}
	attemptCtx, cancel := context.WithTimeout(ctx, policy.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, dest.URL, bytes.NewReader(body))
	if err != nil {
		return d.fail(ctx, del, 0, "", fmt.Sprintf("request could not be built: %v", err), start, false)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "StatusHub/1.0")
	req.Header.Set(SignatureHeader, SignWith(secrets, body, start))
	req.Header.Set("X-StatusHub-Event-Id", event.ID)
	// Which shape this is. A handler that receives something unexpected and
	// cannot say which version it was makes the support conversation start
	// with "what did you send us" rather than with the answer.
	req.Header.Set(SchemaHeader, string(schema))
	req.Header.Set("X-StatusHub-Replay", fmt.Sprintf("%t", del.IsReplay))
	req.Header.Set("X-StatusHub-Attempt", fmt.Sprintf("%d", del.Attempt))
	// The idempotency key is the event ID and not the delivery ID, so a retry
	// and a replay of the same event carry the same key. That is what lets a
	// customer's handler turn our at-least-once into their exactly-once.
	req.Header.Set("Idempotency-Key", event.ID)

	// Offered to any developer listening locally, with the same bytes and the
	// same signature the destination is about to receive — the point of
	// `listen` is developing against the real thing.
	if d.listener != nil {
		d.listener.Publish(event, body, req.Header.Get(SignatureHeader))
	}

	resp, err := d.client.Do(req)
	if err != nil {
		reason := err.Error()
		// A transport failure says something about the destination's health
		// rather than about this event, so it counts towards the breaker.
		d.recordBreaker(dest.ID, false, reason)
		if errors.Is(err, ErrPrivateAddress) {
			// A destination that resolved publicly at registration and
			// privately now is a rebinding attempt, not a typo. It is
			// permanent, loud, and never retried.
			d.log.ErrorContext(ctx, "destination resolved to a private address at delivery time",
				"tenant", del.TenantID, "destination", dest.ID, "url", dest.URL, "error", err)
			return d.fail(ctx, del, 0, "", reason, start, false)
		}
		return d.retry(ctx, del, dest, 0, "", reason, start)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	// Drain the rest so the connection can be reused rather than torn down
	// on every slightly-chatty destination.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	d.metrics.Observe("statushub_delivery_duration_seconds",
		metrics.Labels{"destination": dest.ID}, d.now().Sub(start))

	switch {
	case domain.IsSuccess(resp.StatusCode):
		d.recordBreaker(dest.ID, true, "")
		return d.succeed(ctx, del, resp.StatusCode, string(respBody), start)
	case resp.StatusCode >= 500 || resp.StatusCode == 429:
		// 5xx and 429 are the destination telling us about itself. A 408 is
		// ambiguous enough to retry but not to judge health on.
		d.recordBreaker(dest.ID, false, fmt.Sprintf("destination returned %d", resp.StatusCode))
		return d.retry(ctx, del, dest, resp.StatusCode, string(respBody), "", start)
	case domain.ShouldRetry(resp.StatusCode):
		return d.retry(ctx, del, dest, resp.StatusCode, string(respBody), "", start)
	default:
		// A 4xx is about this payload, not the destination. Counting it would
		// trip the breaker for every other event because one was malformed.
		// A 400 saying the payload is malformed will say the same thing in
		// six hours. Retrying it only delays the dead letter the operator
		// needs to see.
		return d.fail(ctx, del, resp.StatusCode, string(respBody),
			fmt.Sprintf("destination returned %d, which will not change on retry", resp.StatusCode), start, true)
	}
}

// park defers a delivery because the destination's breaker is open.
//
// The attempt counter is rolled back, so an outage does not silently spend
// every queued event's retry budget and dead-letter the lot at the moment the
// customer's service recovers. That would turn a recoverable outage into a
// bulk replay, which is the opposite of what a breaker is for.
func (d *Dispatcher) park(ctx context.Context, del domain.Delivery, dest domain.Destination, why string) error {
	if del.Attempt > 0 {
		del.Attempt--
	}
	del.Status = domain.DeliveryFailed
	del.Error = truncate("parked: " + why)
	del.NextRetryAt = d.now().Add(d.breakerRetryDelay(dest))

	d.metrics.Inc("statushub_deliveries_total", metrics.Labels{
		"destination": dest.ID, "status": "parked",
	})
	d.metrics.Set("statushub_destination_breaker_open",
		metrics.Labels{"destination": dest.ID}, 1)
	return d.store.CompleteDelivery(ctx, del)
}

// breakerRetryDelay is how long a parked delivery waits. Short, because the
// breaker itself decides when the next probe goes out — this only controls
// how often the dispatcher asks.
func (d *Dispatcher) breakerRetryDelay(dest domain.Destination) time.Duration {
	policy := dest.RetryPolicy
	if len(policy.Backoff) == 0 {
		policy = domain.DefaultRetryPolicy()
	}
	if policy.Timeout > 0 && policy.Timeout < 30*time.Second {
		return policy.Timeout
	}
	return 15 * time.Second
}

// recordBreaker feeds an outcome to the breaker and publishes the gauge.
func (d *Dispatcher) recordBreaker(destinationID string, ok bool, reason string) {
	if ok {
		d.breaker.Succeeded(destinationID)
		d.metrics.Set("statushub_destination_breaker_open",
			metrics.Labels{"destination": destinationID}, 0)
		return
	}
	state := d.breaker.Failed(destinationID, reason)
	open := 0.0
	if state != BreakerClosed {
		open = 1
	}
	d.metrics.Set("statushub_destination_breaker_open",
		metrics.Labels{"destination": destinationID}, open)
	if state == BreakerOpen {
		d.log.Warn("destination circuit breaker opened; deliveries are parked without consuming their retry budget",
			"destination", destinationID, "reason", reason)
	}
}

// Breaker exposes the breaker, for the destination-health view and for an
// operator resetting one by hand.
func (d *Dispatcher) Breaker() *Breaker { return d.breaker }

func (d *Dispatcher) succeed(ctx context.Context, del domain.Delivery, code int, body string, start time.Time) error {
	del.Status = domain.DeliverySucceeded
	del.ResponseCode = code
	del.ResponseBody = truncate(body)
	del.DurationMS = int(d.now().Sub(start).Milliseconds())
	del.NextRetryAt = time.Time{}

	d.metrics.Inc("statushub_deliveries_total", metrics.Labels{
		"destination": del.DestinationID, "status": "succeeded",
	})
	d.audit(ctx, domain.AuditRecord{
		TenantID:  del.TenantID,
		EventType: domain.AuditEventForwarded,
		Actor:     domain.Actor{Type: domain.ActorSystem},
		Subject:   domain.Subject{Type: "event", ID: del.EventID},
		Payload: map[string]any{
			"destination": del.DestinationID, "attempt": del.Attempt,
			"response_code": code, "duration_ms": del.DurationMS, "replay": del.IsReplay,
		},
	})
	return d.store.CompleteDelivery(ctx, del)
}

// retry schedules the next attempt, or dead-letters when the budget is spent.
func (d *Dispatcher) retry(ctx context.Context, del domain.Delivery, dest domain.Destination, code int, body, reason string, start time.Time) error {
	policy := dest.RetryPolicy
	if len(policy.Backoff) == 0 {
		policy = domain.DefaultRetryPolicy()
	}

	del.ResponseCode = code
	del.ResponseBody = truncate(body)
	del.Error = truncate(reason)
	del.DurationMS = int(d.now().Sub(start).Milliseconds())

	if del.Attempt >= policy.Attempts() {
		// The budget is spent — but *why* matters, and this is the one place
		// where the breaker changes the outcome rather than only the timing.
		//
		// A retry budget answers "how long do we try this event against a
		// working destination". When the destination is down wholesale, the
		// question is different: the event is fine, and dead-lettering it
		// means an outage silently converts every queued event into something
		// an operator has to find and replay by hand. So while the breaker is
		// open the delivery is parked instead, up to a bounded outage window.
		//
		// The window is what keeps this from being unbounded. Past it, the
		// destination is not having an outage — it is gone — and the events
		// belong in the dead-letter queue where somebody will see them.
		if state := d.breaker.State(dest.ID); state != BreakerClosed &&
			d.now().Sub(del.CreatedAt) < MaxOutageParking {
			return d.park(ctx, del, dest, fmt.Sprintf(
				"destination breaker is %s; the retry budget is not spent during a destination-wide outage", state))
		}

		// Dead-lettering rather than retrying forever is what unblocks the
		// transaction's ordering key: a single unreachable endpoint must not
		// stall a shard indefinitely (§4.5).
		del.Status = domain.DeliveryDeadLetter
		del.NextRetryAt = time.Time{}
		d.metrics.Inc("statushub_dead_letter_total", metrics.Labels{"tenant": del.TenantID})
		d.metrics.Inc("statushub_deliveries_total", metrics.Labels{
			"destination": del.DestinationID, "status": "dead_letter",
		})
		d.log.WarnContext(ctx, "delivery exhausted its retry budget and was dead-lettered",
			"tenant", del.TenantID, "event", del.EventID, "destination", del.DestinationID,
			"attempts", del.Attempt, "last_code", code, "reason", reason)
		d.audit(ctx, domain.AuditRecord{
			TenantID:  del.TenantID,
			EventType: domain.AuditEventDeadLettered,
			Actor:     domain.Actor{Type: domain.ActorSystem},
			Subject:   domain.Subject{Type: "event", ID: del.EventID},
			Payload: map[string]any{
				"destination": del.DestinationID, "attempts": del.Attempt,
				"response_code": code, "reason": reason,
			},
		})
		return d.store.CompleteDelivery(ctx, del)
	}

	del.Status = domain.DeliveryFailed
	del.NextRetryAt = d.now().Add(backoffFor(policy, del.Attempt))
	d.metrics.Inc("statushub_deliveries_total", metrics.Labels{
		"destination": del.DestinationID, "status": "retrying",
	})
	return d.store.CompleteDelivery(ctx, del)
}

// fail records a permanent failure without consuming further attempts.
func (d *Dispatcher) fail(ctx context.Context, del domain.Delivery, code int, body, reason string, start time.Time, deadLetter bool) error {
	del.Status = domain.DeliveryDeadLetter
	del.ResponseCode = code
	del.ResponseBody = truncate(body)
	del.Error = truncate(reason)
	del.DurationMS = int(d.now().Sub(start).Milliseconds())
	del.NextRetryAt = time.Time{}

	d.metrics.Inc("statushub_dead_letter_total", metrics.Labels{"tenant": del.TenantID})
	d.metrics.Inc("statushub_deliveries_total", metrics.Labels{
		"destination": del.DestinationID, "status": "dead_letter",
	})
	d.log.WarnContext(ctx, "delivery failed permanently",
		"tenant", del.TenantID, "event", del.EventID, "destination", del.DestinationID,
		"response_code", code, "reason", reason)
	d.audit(ctx, domain.AuditRecord{
		TenantID:  del.TenantID,
		EventType: domain.AuditEventDeadLettered,
		Actor:     domain.Actor{Type: domain.ActorSystem},
		Subject:   domain.Subject{Type: "event", ID: del.EventID},
		Payload:   map[string]any{"destination": del.DestinationID, "reason": reason, "response_code": code},
	})
	return d.store.CompleteDelivery(ctx, del)
}

// backoffFor returns the wait before attempt n, with jitter.
//
// The jitter is not cosmetic. Without it, a destination that comes back after
// a thirty-minute outage is hit by every pending delivery in the same
// instant, which is how a recovering service is knocked over by the retries
// that were waiting for it.
func backoffFor(p domain.RetryPolicy, attempt int) time.Duration {
	idx := attempt
	if idx >= len(p.Backoff) {
		idx = len(p.Backoff) - 1
	}
	if idx < 0 {
		idx = 0
	}
	base := p.Backoff[idx]
	if base <= 0 || p.JitterFraction <= 0 {
		return base
	}
	spread := float64(base) * p.JitterFraction
	// crypto/rand rather than math/rand: this runs in every replica of a
	// multi-tenant service, and two replicas started from the same seed
	// producing the same jitter would defeat the point of having it.
	n, err := rand.Int(rand.Reader, big.NewInt(int64(2*spread)+1))
	if err != nil {
		return base
	}
	return base + time.Duration(n.Int64()) - time.Duration(spread)
}

func truncate(s string) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) > maxResponseBody {
		return s[:maxResponseBody]
	}
	return s
}

func (d *Dispatcher) audit(ctx context.Context, rec domain.AuditRecord) {
	if err := d.store.AppendAudit(ctx, rec); err != nil {
		d.log.ErrorContext(ctx, "audit append failed",
			"tenant", rec.TenantID, "event_type", rec.EventType, "error", err)
	}
}

// Worker runs the shard loops.
type Worker struct {
	d        *Dispatcher
	interval time.Duration
	lease    time.Duration
	batch    int

	stop sync.Once
	quit chan struct{}
	done chan struct{}
}

// WorkerOptions configure a dispatcher Worker.
type WorkerOptions struct {
	Dispatcher *Dispatcher
	Interval   time.Duration
	Lease      time.Duration
	Batch      int
}

// NewWorker builds a Worker.
func NewWorker(o WorkerOptions) *Worker {
	w := &Worker{
		d: o.Dispatcher, interval: o.Interval, lease: o.Lease, batch: o.Batch,
		quit: make(chan struct{}), done: make(chan struct{}),
	}
	if w.interval <= 0 {
		w.interval = time.Second
	}
	if w.lease <= 0 {
		// Longer than the per-attempt timeout, so a slow destination does not
		// cause a second replica to claim work still in flight.
		w.lease = 2 * time.Minute
	}
	if w.batch <= 0 {
		w.batch = 32
	}
	return w
}

// Run works every shard until the context is cancelled or Stop is called.
func (w *Worker) Run(ctx context.Context) {
	defer close(w.done)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		w.pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-w.quit:
			return
		case <-ticker.C:
		}
	}
}

// Stop asks the worker to finish and waits for it.
func (w *Worker) Stop() {
	w.stop.Do(func() { close(w.quit) })
	<-w.done
}

func (w *Worker) pass(ctx context.Context) {
	now := w.d.now()
	for shard := 0; shard < w.d.shards; shard++ {
		if ctx.Err() != nil {
			return
		}
		claimed, err := w.d.store.ClaimDue(ctx, shard, now, w.batch, w.lease)
		if err != nil {
			w.d.log.ErrorContext(ctx, "could not claim due deliveries", "shard", shard, "error", err)
			continue
		}
		// Deliveries within a shard run sequentially. ClaimDue already
		// guarantees at most one in flight per transaction reference; running
		// the claimed batch in order keeps a shard's own concurrency
		// predictable, and parallelism comes from there being many shards.
		for _, del := range claimed {
			if ctx.Err() != nil {
				return
			}
			if err := w.d.DeliverOnce(ctx, del); err != nil {
				w.d.log.ErrorContext(ctx, "delivery attempt could not be recorded",
					"delivery", del.ID, "event", del.EventID, "error", err)
			}
		}
	}
	w.reportQueues(ctx)
}

// reportQueues publishes the two gauges the scaling signal and the
// head-of-line-blocking alert are built on (§11.4).
func (w *Worker) reportQueues(ctx context.Context) {
	depth, err := w.d.store.QueueDepth(ctx)
	if err == nil {
		for shard, n := range depth {
			w.d.metrics.Set("statushub_delivery_queue_depth",
				metrics.Labels{"shard": fmt.Sprintf("%d", shard)}, float64(n))
		}
	}
	oldest, err := w.d.store.OldestPending(ctx)
	if err == nil {
		now := w.d.now()
		for shard, t := range oldest {
			w.d.metrics.Set("statushub_shard_oldest_pending_seconds",
				metrics.Labels{"shard": fmt.Sprintf("%d", shard)}, now.Sub(t).Seconds())
		}
	}
}
