package normalise

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Worker drives normalisation from two sources at once: notifications from
// the receiver, and a periodic sweep of anything the notifications missed.
//
// Both exist on purpose. Notifications make the common case fast — an event
// is normalised milliseconds after it arrives. The sweep makes the system
// correct: a notification is an in-memory signal that a restart loses, and a
// design where a lost signal means a lost event is a design that loses events
// on every deploy. The sweep is the reason the receiver can drop a
// notification without consequence.
type Worker struct {
	n        *Normaliser
	log      *slog.Logger
	interval time.Duration
	batch    int

	// notifications is buffered and lossy. A full channel drops the signal
	// rather than blocking the receiver's response path — the sweep will pick
	// the event up within one interval, and a slow normaliser must never
	// become a slow receiver.
	notifications chan string

	started sync.Once
	stopped chan struct{}
	done    chan struct{}
}

// WorkerOptions configure a Worker.
type WorkerOptions struct {
	Normaliser *Normaliser
	Logger     *slog.Logger

	// Interval is how often the sweep runs. It is the upper bound on how long
	// a dropped notification delays an event.
	Interval time.Duration

	// Batch is how many pending raw events one sweep claims.
	Batch int

	// Buffer sizes the notification channel.
	Buffer int
}

// NewWorker builds a Worker.
func NewWorker(o WorkerOptions) *Worker {
	w := &Worker{
		n:        o.Normaliser,
		log:      o.Logger,
		interval: o.Interval,
		batch:    o.Batch,
		stopped:  make(chan struct{}),
		done:     make(chan struct{}),
	}
	if w.log == nil {
		w.log = slog.Default()
	}
	if w.interval <= 0 {
		w.interval = 2 * time.Second
	}
	if w.batch <= 0 {
		w.batch = 100
	}
	buffer := o.Buffer
	if buffer <= 0 {
		buffer = 1024
	}
	w.notifications = make(chan string, buffer)
	return w
}

// Notify implements receive.Notifier. It never blocks and never fails: the
// receiver has already answered the provider, and nothing on that path may
// wait on this one.
func (w *Worker) Notify(rawEventID string) {
	select {
	case w.notifications <- rawEventID:
	default:
		// Dropped. The sweep will find it. Counted at debug rather than warn
		// because a burst that outruns the buffer is normal under load and
		// costs latency, not correctness.
		w.log.Debug("normalisation notification dropped; the sweep will pick it up",
			"raw_event", rawEventID)
	}
}

// Run works until the context is cancelled or Stop is called.
func (w *Worker) Run(ctx context.Context) {
	defer close(w.done)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// An immediate sweep on start, so a restart does not wait a full interval
	// before picking up whatever the previous process left behind.
	w.sweep(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopped:
			return
		case <-w.notifications:
			// The identifier is not used. Draining the channel is a signal
			// that work exists, and the sweep is the thing that decides what
			// to do — which means the notification path and the recovery path
			// are the same code, and the recovery path is therefore exercised
			// on every single event rather than only after a crash.
			w.sweep(ctx)
		case <-ticker.C:
			w.sweep(ctx)
		}
	}
}

// Stop asks the worker to finish and waits for it.
func (w *Worker) Stop() {
	w.started.Do(func() { close(w.stopped) })
	<-w.done
}

func (w *Worker) sweep(ctx context.Context) {
	pending, err := w.n.store.ListUnnormalised(ctx, w.batch)
	if err != nil {
		w.log.ErrorContext(ctx, "could not list events awaiting normalisation", "error", err)
		return
	}
	for _, raw := range pending {
		if ctx.Err() != nil {
			return
		}
		err := w.n.Process(ctx, raw.ID, raw.TenantID)
		switch {
		case err == nil:
		case errors.Is(err, ErrNotNormalisable):
			// Already recorded against the raw event, which is what stops it
			// being returned by the next sweep. Nothing further to do: the
			// operator sees it in the mapping-incomplete view.
		default:
			// Transient. Left pending so the next sweep tries again.
			w.log.ErrorContext(ctx, "normalisation failed and will be retried",
				"raw_event", raw.ID, "tenant", raw.TenantID, "error", err)
		}
	}
}
