package dispatch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

// MaxBulkReplay bounds one bulk replay request.
//
// Ten thousand. Replay is the recovery tool for a bad deploy, so the number
// has to be large enough to cover a real outage window — but a replay is also
// the easiest way for an operator to accidentally send a customer's own
// system a million requests at four in the morning, and an unbounded one
// offers no moment at which anybody notices.
const MaxBulkReplay = 10_000

// ReplayRequest describes what to replay (§3.2 C3).
type ReplayRequest struct {
	// EventIDs replays exactly these. Mutually exclusive with Filter.
	EventIDs []string

	// Filter replays everything matching, within the time range.
	Filter *store.EventQuery

	// DestinationIDs limits which destinations receive the replay. Empty
	// means every enabled destination whose filter matches — which is what an
	// operator recovering from their own outage wants, and is why it is the
	// default rather than something to opt into under pressure.
	DestinationIDs []string

	// DryRun counts and reports without queueing anything. Present because
	// the first thing anyone should do with a bulk replay is find out how big
	// it is.
	DryRun bool
}

// ReplayResult reports what a replay did, or would do.
type ReplayResult struct {
	Matched      int      `json:"matched"`
	Queued       int      `json:"queued"`
	Destinations []string `json:"destinations"`
	DryRun       bool     `json:"dry_run"`
	Truncated    bool     `json:"truncated"`
	Note         string   `json:"note,omitempty"`
}

// ErrReplayTooLarge means the request matched more than MaxBulkReplay events.
var ErrReplayTooLarge = errors.New("replay matches more events than one request may queue")

// Replay re-delivers stored events.
//
// Nothing is re-normalised. The canonical event that was produced is the one
// that is sent again, which means a replay reproduces exactly what the
// customer would have received the first time. Re-running the adapter would
// be a different feature — useful after fixing a mapping, and deliberately
// separate, because an operator replaying a delivery outage must not silently
// get different payloads because someone changed an adapter last week.
func (d *Dispatcher) Replay(ctx context.Context, tenantID string, req ReplayRequest) (ReplayResult, error) {
	res := ReplayResult{DryRun: req.DryRun}

	destinations, err := d.resolveDestinations(ctx, tenantID, req.DestinationIDs)
	if err != nil {
		return res, err
	}
	if len(destinations) == 0 {
		return res, errors.New("no enabled destination to replay to")
	}
	for _, dest := range destinations {
		res.Destinations = append(res.Destinations, dest.ID)
	}

	events, truncated, err := d.resolveEvents(ctx, tenantID, req)
	if err != nil {
		return res, err
	}
	res.Matched = len(events)
	res.Truncated = truncated
	if truncated {
		res.Note = fmt.Sprintf("capped at %d events; narrow the time range and replay again", MaxBulkReplay)
	}

	if req.DryRun {
		return res, nil
	}

	for _, ev := range events {
		for _, dest := range destinations {
			// The destination's filter still applies. A replay that ignored
			// it would send an analytics sink the pending events it
			// deliberately excluded, which is a surprise nobody wants during
			// a recovery.
			if !dest.Filter.Matches(&ev) {
				continue
			}
			if _, err := d.EnqueueReplay(ctx, ev, dest.ID); err != nil {
				return res, fmt.Errorf("queueing replay of %s to %s: %w", ev.ID, dest.ID, err)
			}
			res.Queued++
		}
	}

	d.log.InfoContext(ctx, "replay queued",
		"tenant", tenantID, "matched", res.Matched, "queued", res.Queued,
		"destinations", len(destinations), "truncated", truncated)
	return res, nil
}

func (d *Dispatcher) resolveDestinations(ctx context.Context, tenantID string, ids []string) ([]domain.Destination, error) {
	if len(ids) > 0 {
		out := make([]domain.Destination, 0, len(ids))
		for _, id := range ids {
			dest, err := d.store.GetDestination(ctx, tenantID, id)
			if err != nil {
				return nil, fmt.Errorf("destination %s: %w", id, err)
			}
			if !dest.Enabled {
				return nil, fmt.Errorf("destination %s is disabled", id)
			}
			out = append(out, dest)
		}
		return out, nil
	}

	all, err := d.store.ListDestinations(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Destination, 0, len(all))
	for _, dest := range all {
		if dest.Enabled {
			out = append(out, dest)
		}
	}
	return out, nil
}

func (d *Dispatcher) resolveEvents(ctx context.Context, tenantID string, req ReplayRequest) ([]domain.CanonicalEvent, bool, error) {
	if len(req.EventIDs) > 0 && req.Filter != nil {
		return nil, false, errors.New("replay by event ID and replay by filter are mutually exclusive")
	}

	if len(req.EventIDs) > 0 {
		if len(req.EventIDs) > MaxBulkReplay {
			return nil, false, ErrReplayTooLarge
		}
		out := make([]domain.CanonicalEvent, 0, len(req.EventIDs))
		for _, id := range req.EventIDs {
			ev, err := d.store.GetCanonicalEvent(ctx, tenantID, id)
			if err != nil {
				// Named, so an operator pasting a list of IDs learns which
				// one was wrong rather than that "something" was.
				return nil, false, fmt.Errorf("event %s: %w", id, err)
			}
			out = append(out, ev)
		}
		return out, false, nil
	}

	if req.Filter == nil {
		return nil, false, errors.New("replay needs either event IDs or a filter")
	}

	// Paged rather than fetched in one query: a replay window can legitimately
	// be a whole day, and loading a day of events into one slice is how a
	// recovery tool becomes the second outage.
	q := *req.Filter
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 500
	}
	var (
		out       []domain.CanonicalEvent
		truncated bool
	)
	for {
		page, err := d.store.QueryEvents(ctx, tenantID, q)
		if err != nil {
			return nil, false, err
		}
		if len(page) == 0 {
			break
		}
		for _, ev := range page {
			if len(out) >= MaxBulkReplay {
				truncated = true
				break
			}
			out = append(out, ev)
		}
		if truncated || len(page) < q.Limit {
			break
		}
		q.Cursor = page[len(page)-1].ID
	}
	return out, truncated, nil
}

// RetryDeadLetter re-queues a single dead-lettered delivery (§7.3).
//
// It creates a new delivery rather than resetting the old one. The dead
// letter is evidence — it records what the destination said and when — and
// overwriting it to try again would destroy the record of the failure that
// prompted the retry.
func (d *Dispatcher) RetryDeadLetter(ctx context.Context, tenantID string, deliveryID int64) (int64, error) {
	del, err := d.store.GetDelivery(ctx, tenantID, deliveryID)
	if err != nil {
		return 0, err
	}
	if del.Status != domain.DeliveryDeadLetter {
		return 0, fmt.Errorf("delivery %d is %s, not dead-lettered", deliveryID, del.Status)
	}
	ev, err := d.store.GetCanonicalEvent(ctx, tenantID, del.EventID)
	if err != nil {
		return 0, err
	}
	return d.EnqueueReplay(ctx, ev, del.DestinationID)
}

// SweepUndelivered finds canonical events with no delivery at all and queues
// them.
//
// This is the safety net for a normaliser that stored an event and then
// failed to queue it — a crash in that window, or a transient error from the
// enqueue. Without it, such an event is stored, searchable, and silently
// never forwarded, which is the worst combination available: it looks fine
// everywhere an operator would think to check.
func (d *Dispatcher) SweepUndelivered(ctx context.Context, tenantID string, since time.Time, limit int) (int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	events, err := d.store.QueryEvents(ctx, tenantID, store.EventQuery{From: since, Limit: limit})
	if err != nil {
		return 0, err
	}
	var queued int
	for _, ev := range events {
		existing, err := d.store.ListDeliveriesForEvent(ctx, tenantID, ev.ID)
		if err != nil {
			return queued, err
		}
		if len(existing) > 0 {
			continue
		}
		if err := d.Enqueue(ctx, ev); err != nil {
			return queued, err
		}
		queued++
	}
	if queued > 0 {
		d.log.WarnContext(ctx, "queued events that had been normalised but never handed to delivery",
			"tenant", tenantID, "count", queued)
	}
	return queued, nil
}
