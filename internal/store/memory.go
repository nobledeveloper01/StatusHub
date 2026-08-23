package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// Memory is an in-memory Store. It backs the unit tests and `statushub serve
// --store memory`, which is enough to evaluate the product end to end without
// provisioning anything.
//
// It is not a toy: it enforces the same tenant scoping, the same duplicate
// rejection and the same audit chaining as Postgres, because a test suite
// running against a permissive fake proves nothing about the strict thing.
// What it does not do is survive a restart, which is why it refuses to start
// in the live environment.
type Memory struct {
	mu sync.RWMutex

	tenants      map[string]domain.Tenant
	tenantBySlug map[string]string

	endpoints    map[string]domain.Endpoint
	destinations map[string]domain.Destination

	rawEvents  map[string]domain.RawEvent
	rawOrder   []string
	normalised map[string]string // rawEventID -> canonical event ID
	failures   map[string]string // rawEventID -> reason

	events    map[string]domain.CanonicalEvent
	eventKeys map[string]string // tenant|provider|providerEventID -> event ID
	eventList []string

	deliveries  map[int64]domain.Delivery
	deliveryIDs int64
	sequences   map[string]int64 // tenant|transactionRef -> last sequence
	leases      map[int64]time.Time

	audit     map[string][]domain.AuditRecord
	auditHead map[string]string
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		tenants:      map[string]domain.Tenant{},
		tenantBySlug: map[string]string{},
		endpoints:    map[string]domain.Endpoint{},
		destinations: map[string]domain.Destination{},
		rawEvents:    map[string]domain.RawEvent{},
		normalised:   map[string]string{},
		failures:     map[string]string{},
		events:       map[string]domain.CanonicalEvent{},
		eventKeys:    map[string]string{},
		deliveries:   map[int64]domain.Delivery{},
		sequences:    map[string]int64{},
		leases:       map[int64]time.Time{},
		audit:        map[string][]domain.AuditRecord{},
		auditHead:    map[string]string{},
	}
}

func (m *Memory) Health(context.Context) error { return nil }
func (m *Memory) Close() error                 { return nil }

// --- Tenants ---

func (m *Memory) CreateTenant(_ context.Context, t domain.Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenantBySlug[t.Slug]; ok {
		return fmt.Errorf("%w: tenant slug %q", ErrDuplicate, t.Slug)
	}
	m.tenants[t.ID] = t
	m.tenantBySlug[t.Slug] = t.ID
	return nil
}

func (m *Memory) GetTenant(_ context.Context, tenantID string) (domain.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tenants[tenantID]
	if !ok {
		return domain.Tenant{}, ErrNotFound
	}
	return t, nil
}

func (m *Memory) GetTenantBySlug(_ context.Context, slug string) (domain.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.tenantBySlug[slug]
	if !ok {
		return domain.Tenant{}, ErrNotFound
	}
	return m.tenants[id], nil
}

func (m *Memory) ListTenants(context.Context) ([]domain.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

// --- Endpoints ---

func (m *Memory) CreateEndpoint(_ context.Context, e domain.Endpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.endpoints {
		if existing.ReceiverToken == e.ReceiverToken {
			return fmt.Errorf("%w: receiver token", ErrDuplicate)
		}
	}
	m.endpoints[e.ID] = e
	return nil
}

func (m *Memory) GetEndpoint(_ context.Context, tenantID, endpointID string) (domain.Endpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.endpoints[endpointID]
	// The tenant check and the existence check produce the same error, on
	// purpose. See ErrNotFound.
	if !ok || e.TenantID != tenantID {
		return domain.Endpoint{}, ErrNotFound
	}
	return e, nil
}

func (m *Memory) ListEndpoints(_ context.Context, tenantID string) ([]domain.Endpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []domain.Endpoint
	for _, e := range m.endpoints {
		if e.TenantID == tenantID {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) UpdateEndpoint(_ context.Context, tenantID string, e domain.Endpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.endpoints[e.ID]
	if !ok || existing.TenantID != tenantID {
		return ErrNotFound
	}
	e.TenantID = tenantID
	m.endpoints[e.ID] = e
	return nil
}

func (m *Memory) DeleteEndpoint(_ context.Context, tenantID, endpointID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.endpoints[endpointID]
	if !ok || e.TenantID != tenantID {
		return ErrNotFound
	}
	delete(m.endpoints, endpointID)
	return nil
}

func (m *Memory) ResolveReceiver(_ context.Context, tenantSlug, provider, env, token string) (domain.Endpoint, domain.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tenantID, ok := m.tenantBySlug[tenantSlug]
	if !ok {
		return domain.Endpoint{}, domain.Tenant{}, ErrNotFound
	}
	for _, e := range m.endpoints {
		if e.TenantID != tenantID || e.ReceiverToken != token {
			continue
		}
		// Every component of the URL must agree. A token is scoped to the
		// exact endpoint it was issued for, so a live token cannot be
		// replayed against the test endpoint or against another provider's.
		if e.Provider != provider || string(e.Environment) != env {
			return domain.Endpoint{}, domain.Tenant{}, ErrNotFound
		}
		return e, m.tenants[tenantID], nil
	}
	return domain.Endpoint{}, domain.Tenant{}, ErrNotFound
}

// --- Destinations ---

func (m *Memory) CreateDestination(_ context.Context, d domain.Destination) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.destinations[d.ID] = d
	return nil
}

func (m *Memory) GetDestination(_ context.Context, tenantID, id string) (domain.Destination, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.destinations[id]
	if !ok || d.TenantID != tenantID {
		return domain.Destination{}, ErrNotFound
	}
	return d, nil
}

func (m *Memory) ListDestinations(_ context.Context, tenantID string) ([]domain.Destination, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []domain.Destination
	for _, d := range m.destinations {
		if d.TenantID == tenantID {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) UpdateDestination(_ context.Context, tenantID string, d domain.Destination) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.destinations[d.ID]
	if !ok || existing.TenantID != tenantID {
		return ErrNotFound
	}
	d.TenantID = tenantID
	m.destinations[d.ID] = d
	return nil
}

func (m *Memory) DeleteDestination(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.destinations[id]
	if !ok || d.TenantID != tenantID {
		return ErrNotFound
	}
	delete(m.destinations, id)
	return nil
}

// --- Raw events ---

func (m *Memory) PutRawEvent(_ context.Context, e domain.RawEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rawEvents[e.ID]; ok {
		return ErrDuplicate
	}
	m.rawEvents[e.ID] = e
	m.rawOrder = append(m.rawOrder, e.ID)
	return nil
}

func (m *Memory) GetRawEvent(_ context.Context, tenantID, id string) (domain.RawEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.rawEvents[id]
	if !ok || e.TenantID != tenantID {
		return domain.RawEvent{}, ErrNotFound
	}
	return e, nil
}

func (m *Memory) ListUnnormalised(_ context.Context, limit int) ([]domain.RawEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	var out []domain.RawEvent
	for _, id := range m.rawOrder {
		e := m.rawEvents[id]
		// An event whose signature failed is never normalised and never
		// forwarded (§10.1). It is kept as forensic evidence, which is a
		// different job from being pending work.
		if !e.SignatureValid {
			continue
		}
		if _, done := m.normalised[id]; done {
			continue
		}
		if _, failed := m.failures[id]; failed {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *Memory) ListSignatureFailures(_ context.Context, tenantID, endpointID string, since time.Time, limit int) ([]domain.RawEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	var out []domain.RawEvent
	for i := len(m.rawOrder) - 1; i >= 0 && len(out) < limit; i-- {
		e := m.rawEvents[m.rawOrder[i]]
		if e.TenantID != tenantID || e.SignatureValid {
			continue
		}
		if endpointID != "" && e.EndpointID != endpointID {
			continue
		}
		if !since.IsZero() && e.ReceivedAt.Before(since) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// --- Canonical events ---

func (m *Memory) PutCanonicalEvent(_ context.Context, e domain.CanonicalEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.ProviderEventID != "" {
		key := e.TenantID + "|" + e.Provider + "|" + e.ProviderEventID
		if existing, ok := m.eventKeys[key]; ok {
			return fmt.Errorf("%w: %s", ErrDuplicate, existing)
		}
		m.eventKeys[key] = e.ID
	}
	m.events[e.ID] = e
	m.eventList = append(m.eventList, e.ID)
	if e.RawEventID != "" {
		m.normalised[e.RawEventID] = e.ID
	}
	return nil
}

func (m *Memory) GetCanonicalEvent(_ context.Context, tenantID, id string) (domain.CanonicalEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.events[id]
	if !ok || e.TenantID != tenantID {
		return domain.CanonicalEvent{}, ErrNotFound
	}
	return e, nil
}

func (m *Memory) GetCanonicalEventByDedupeKey(_ context.Context, tenantID, provider, providerEventID string) (domain.CanonicalEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.eventKeys[tenantID+"|"+provider+"|"+providerEventID]
	if !ok {
		return domain.CanonicalEvent{}, ErrNotFound
	}
	return m.events[id], nil
}

func (m *Memory) QueryEvents(_ context.Context, tenantID string, q EventQuery) ([]domain.CanonicalEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []domain.CanonicalEvent
	// Newest first: the event explorer is opened during an incident, and the
	// event being investigated is almost always the most recent one.
	for i := len(m.eventList) - 1; i >= 0 && len(out) < limit; i-- {
		e := m.events[m.eventList[i]]
		if e.TenantID != tenantID || !matches(e, q) {
			continue
		}
		if q.Cursor != "" && e.ID >= q.Cursor {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func matches(e domain.CanonicalEvent, q EventQuery) bool {
	if q.Provider != "" && !strings.EqualFold(e.Provider, q.Provider) {
		return false
	}
	if q.Status != "" && e.Status != q.Status {
		return false
	}
	if q.EventType != "" && e.EventType != q.EventType {
		return false
	}
	if q.TransactionRef != "" && e.TransactionRef != q.TransactionRef {
		return false
	}
	if q.MappingComplete != nil && e.MappingComplete != *q.MappingComplete {
		return false
	}
	if !q.From.IsZero() && e.OccurredAt.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && e.OccurredAt.After(q.To) {
		return false
	}
	return true
}

func (m *Memory) MarkNormalisationFailure(_ context.Context, tenantID, rawEventID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.rawEvents[rawEventID]
	if !ok || e.TenantID != tenantID {
		return ErrNotFound
	}
	m.failures[rawEventID] = reason
	return nil
}

func (m *Memory) UnknownStatuses(_ context.Context, tenantID string, since time.Time) ([]UnknownStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agg := map[string]*UnknownStatus{}
	for _, id := range m.eventList {
		e := m.events[id]
		if e.TenantID != tenantID || e.UnmappedStatus == "" {
			continue
		}
		if !since.IsZero() && e.NormalisedAt.Before(since) {
			continue
		}
		key := e.Provider + "|" + e.UnmappedStatus
		u, ok := agg[key]
		if !ok {
			agg[key] = &UnknownStatus{
				Provider: e.Provider, RawValue: e.UnmappedStatus, Count: 1,
				FirstSeen: e.NormalisedAt, LastSeen: e.NormalisedAt, SampleEvent: e.ID,
			}
			continue
		}
		u.Count++
		if e.NormalisedAt.Before(u.FirstSeen) {
			u.FirstSeen = e.NormalisedAt
		}
		if e.NormalisedAt.After(u.LastSeen) {
			u.LastSeen = e.NormalisedAt
		}
	}
	out := make([]UnknownStatus, 0, len(agg))
	for _, u := range agg {
		out = append(out, *u)
	}
	// Most frequent first: that is the adapter fix worth doing next.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].RawValue < out[j].RawValue
	})
	return out, nil
}

// Compile-time proof that the in-memory store implements the whole interface.
// Without it, a method added to Store would only fail where Memory is passed
// as one — which in practice is inside a test, at the point least useful for
// diagnosing it.
var _ Store = (*Memory)(nil)
