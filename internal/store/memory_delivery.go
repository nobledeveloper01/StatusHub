package store

import (
	"context"
	"sort"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// --- Deliveries ---

func (m *Memory) EnqueueDelivery(_ context.Context, d domain.Delivery) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deliveryIDs++
	d.ID = m.deliveryIDs
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	d.UpdatedAt = d.CreatedAt
	m.deliveries[d.ID] = d
	return d.ID, nil
}

func (m *Memory) NextSequence(_ context.Context, tenantID, transactionRef string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID + "|" + transactionRef
	m.sequences[key]++
	return m.sequences[key], nil
}

// ClaimDue leases the deliveries a dispatcher may attempt now.
//
// The ordering rule lives here rather than in the dispatcher, and it is one
// rule: at most one in-flight delivery per (destination, transaction
// reference). Two events about one transaction can therefore never be in
// flight at once, so a `success` cannot overtake the `pending` that preceded
// it (§3.2 C2). Different references are unaffected and run in parallel,
// which is the whole reason for sharding rather than serialising.
func (m *Memory) ClaimDue(_ context.Context, shard int, now time.Time, limit int, lease time.Duration) ([]domain.Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 {
		limit = 32
	}
	if lease <= 0 {
		lease = time.Minute
	}

	// Which (destination, ref) pairs already have something in flight. A
	// lease that has expired does not count: the dispatcher holding it is
	// gone, and refusing to reclaim the work would stall the key forever.
	blocked := map[string]struct{}{}
	for id, d := range m.deliveries {
		if d.Status != domain.DeliveryInFlight {
			continue
		}
		if exp, ok := m.leases[id]; ok && exp.Before(now) {
			continue
		}
		blocked[d.DestinationID+"|"+m.refFor(d)] = struct{}{}
	}

	candidates := make([]domain.Delivery, 0, len(m.deliveries))
	for _, d := range m.deliveries {
		if d.Shard != shard || d.Status.IsTerminal() {
			continue
		}
		if d.Status == domain.DeliveryInFlight {
			if exp, ok := m.leases[d.ID]; ok && exp.After(now) {
				continue
			}
		}
		if !d.NextRetryAt.IsZero() && d.NextRetryAt.After(now) {
			continue
		}
		candidates = append(candidates, d)
	}

	// Sequence order within a reference, then oldest first. Sorting by
	// sequence before claiming is what makes the one-in-flight rule produce
	// ordering rather than merely serialisation.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Sequence != candidates[j].Sequence {
			return candidates[i].Sequence < candidates[j].Sequence
		}
		return candidates[i].ID < candidates[j].ID
	})

	var claimed []domain.Delivery
	for _, d := range candidates {
		if len(claimed) >= limit {
			break
		}
		key := d.DestinationID + "|" + m.refFor(d)
		if _, taken := blocked[key]; taken {
			continue
		}
		blocked[key] = struct{}{}

		d.Status = domain.DeliveryInFlight
		d.Attempt++
		d.UpdatedAt = now
		m.deliveries[d.ID] = d
		m.leases[d.ID] = now.Add(lease)
		claimed = append(claimed, d)
	}
	return claimed, nil
}

// refFor resolves a delivery's transaction reference through its event.
// Callers hold m.mu.
func (m *Memory) refFor(d domain.Delivery) string {
	if e, ok := m.events[d.EventID]; ok {
		return e.TransactionRef
	}
	return d.EventID
}

func (m *Memory) CompleteDelivery(_ context.Context, d domain.Delivery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.deliveries[d.ID]
	if !ok || existing.TenantID != d.TenantID {
		return ErrNotFound
	}
	d.CreatedAt = existing.CreatedAt
	d.UpdatedAt = time.Now().UTC()
	m.deliveries[d.ID] = d
	delete(m.leases, d.ID)
	return nil
}

func (m *Memory) GetDelivery(_ context.Context, tenantID string, id int64) (domain.Delivery, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.deliveries[id]
	if !ok || d.TenantID != tenantID {
		return domain.Delivery{}, ErrNotFound
	}
	return d, nil
}

func (m *Memory) ListDeliveriesForEvent(_ context.Context, tenantID, eventID string) ([]domain.Delivery, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []domain.Delivery
	for _, d := range m.deliveries {
		if d.TenantID == tenantID && d.EventID == eventID {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) QueryDeliveries(_ context.Context, tenantID string, q DeliveryQuery) ([]domain.Delivery, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []domain.Delivery
	ids := make([]int64, 0, len(m.deliveries))
	for id := range m.deliveries {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] > ids[j] })
	for _, id := range ids {
		if len(out) >= limit {
			break
		}
		d := m.deliveries[id]
		if d.TenantID != tenantID {
			continue
		}
		if q.DestinationID != "" && d.DestinationID != q.DestinationID {
			continue
		}
		if q.Status != "" && d.Status != q.Status {
			continue
		}
		if q.EventID != "" && d.EventID != q.EventID {
			continue
		}
		if !q.From.IsZero() && d.CreatedAt.Before(q.From) {
			continue
		}
		if !q.To.IsZero() && d.CreatedAt.After(q.To) {
			continue
		}
		if q.Cursor != 0 && d.ID >= q.Cursor {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

func (m *Memory) QueueDepth(context.Context) (map[int]int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[int]int64{}
	for _, d := range m.deliveries {
		if !d.Status.IsTerminal() {
			out[d.Shard]++
		}
	}
	return out, nil
}

// OldestPending backs statushub_shard_oldest_pending_seconds, which is how
// head-of-line blocking is detected before a customer reports it (§11.4).
func (m *Memory) OldestPending(context.Context) (map[int]time.Time, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[int]time.Time{}
	for _, d := range m.deliveries {
		if d.Status.IsTerminal() {
			continue
		}
		if cur, ok := out[d.Shard]; !ok || d.CreatedAt.Before(cur) {
			out[d.Shard] = d.CreatedAt
		}
	}
	return out, nil
}
