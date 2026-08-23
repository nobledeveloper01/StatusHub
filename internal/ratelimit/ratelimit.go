// Package ratelimit is the explicit backpressure §8.6 requires.
//
// The principle it implements: when capacity is exceeded, say so with a 429
// and a Retry-After, rather than silently queueing until the process dies.
// Unbounded growth is the most common cause of a 3am page, and a receiver
// that accepts everything until it runs out of memory does not fail gracefully
// — it fails for every tenant at once, including the ones behaving perfectly.
//
// The receiver's limits are deliberately generous and its refusal is
// deliberately loud. A refused webhook is an event lost, because the provider
// may exhaust its retries against our 429. So the ceiling exists to stop one
// tenant taking the service down for everybody, not to shape traffic — and it
// is set far above any legitimate volume.
package ratelimit

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// Limiter is a per-key token bucket.
//
// A bucket rather than a fixed window, because a fixed window lets a tenant
// send their whole minute's allowance in the first second and then take the
// service down for the other fifty-nine. A bucket smooths that while still
// permitting a genuine burst up to its capacity — which matters here, since
// providers legitimately deliver in bursts after their own outages.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	rate     float64 // tokens per second
	capacity float64

	// idleAfter is when an untouched bucket is forgotten. Without it the map
	// grows with every tenant that has ever sent a webhook, which is a slow
	// memory leak keyed on customer count.
	idleAfter time.Duration

	now func() time.Time
}

type bucket struct {
	tokens   float64
	lastFill time.Time
	lastSeen time.Time

	// refused counts rejections, so the dashboard can show a tenant that is
	// being throttled rather than leaving them to discover it from their
	// provider's dashboard.
	refused int64
}

// Options configure a Limiter.
type Options struct {
	// PerSecond is the sustained rate.
	PerSecond float64

	// Burst is the bucket's capacity — how far above the sustained rate a
	// momentary spike may go.
	Burst float64

	IdleAfter time.Duration
	Now       func() time.Time
}

// New builds a Limiter.
func New(o Options) *Limiter {
	l := &Limiter{
		buckets:   map[string]*bucket{},
		rate:      o.PerSecond,
		capacity:  o.Burst,
		idleAfter: o.IdleAfter,
		now:       o.Now,
	}
	if l.rate <= 0 {
		l.rate = 1000
	}
	if l.capacity <= 0 {
		l.capacity = l.rate * 2
	}
	if l.idleAfter <= 0 {
		l.idleAfter = 10 * time.Minute
	}
	if l.now == nil {
		l.now = func() time.Time { return time.Now().UTC() }
	}
	return l
}

// Decision is the outcome of a limit check.
type Decision struct {
	Allowed bool

	// RetryAfter is how long the caller should wait. It is always populated
	// on a refusal, because a 429 without one leaves the caller guessing and
	// most providers guess badly — either hammering immediately or backing
	// off for hours.
	RetryAfter time.Duration

	// Remaining is the tokens left, for the response headers.
	Remaining float64
	Limit     float64
}

// Header renders Retry-After's value in seconds, rounded up. Zero seconds
// would tell a caller to retry immediately, which is never what a refusal
// means.
func (d Decision) Header() string {
	s := int(math.Ceil(d.RetryAfter.Seconds()))
	if s < 1 {
		s = 1
	}
	return fmt.Sprintf("%d", s)
}

// Allow takes one token for key.
func (l *Limiter) Allow(key string) Decision {
	return l.AllowN(key, 1)
}

// AllowN takes n tokens.
func (l *Limiter) AllowN(key string, n float64) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.capacity, lastFill: now}
		l.buckets[key] = b
	}

	// Refill for the elapsed time, capped at the bucket's size.
	elapsed := now.Sub(b.lastFill).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(l.capacity, b.tokens+elapsed*l.rate)
		b.lastFill = now
	}
	b.lastSeen = now

	if b.tokens >= n {
		b.tokens -= n
		return Decision{Allowed: true, Remaining: b.tokens, Limit: l.capacity}
	}

	// How long until enough tokens exist. Told precisely rather than as a
	// fixed guess, so a caller that honours Retry-After succeeds on its next
	// attempt instead of being refused again.
	deficit := n - b.tokens
	b.refused++
	return Decision{
		Allowed:    false,
		RetryAfter: time.Duration(deficit / l.rate * float64(time.Second)),
		Remaining:  0,
		Limit:      l.capacity,
	}
}

// Refused reports how many requests a key has had rejected.
func (l *Limiter) Refused(key string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.buckets[key]; ok {
		return b.refused
	}
	return 0
}

// Sweep forgets buckets nobody has touched, so the map does not grow with
// every tenant that has ever sent a webhook.
func (l *Limiter) Sweep() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := l.now().Add(-l.idleAfter)
	var removed int
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
			removed++
		}
	}
	return removed
}

// Tracked reports how many keys are held, for the memory-growth metric.
func (l *Limiter) Tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Bounded is a counting semaphore with an explicit ceiling.
//
// Every queue, buffer and in-flight set in the system has one of these or an
// equivalent. The rule from §8.6 is that nothing grows without a stated
// limit, because an unbounded queue does not fail — it degrades silently
// until the process is killed, taking whatever was in the queue with it.
type Bounded struct {
	slots chan struct{}
	name  string
}

// NewBounded returns a semaphore of the given size.
func NewBounded(name string, size int) *Bounded {
	if size <= 0 {
		size = 1
	}
	return &Bounded{slots: make(chan struct{}, size), name: name}
}

// TryAcquire takes a slot without blocking. Blocking would convert a capacity
// problem into a latency problem, and the receiver's whole design is that it
// answers fast or says no.
func (b *Bounded) TryAcquire() bool {
	select {
	case b.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release returns a slot.
func (b *Bounded) Release() {
	select {
	case <-b.slots:
	default:
		// Releasing more than was acquired is a bug in the caller. Panicking
		// here would take down a process over a leak; silently ignoring it
		// keeps the ceiling honest, and the InUse gauge makes the leak
		// visible.
	}
}

// InUse is how many slots are held.
func (b *Bounded) InUse() int { return len(b.slots) }

// Capacity is the ceiling.
func (b *Bounded) Capacity() int { return cap(b.slots) }

// Name identifies the semaphore in metrics and logs.
func (b *Bounded) Name() string { return b.name }
