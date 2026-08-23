// Package store is the persistence boundary. Two implementations satisfy it:
// an in-memory one for tests and single-node evaluation, and Postgres for
// everything else.
//
// Every method that touches tenant-owned data takes tenantID as its first
// argument, and no method exists that does not. That is layer two of the
// three-layer tenancy model (§8.1), and the reason it is expressed in the
// interface rather than in a convention is that a forgotten scope then fails
// to compile instead of returning another tenant's rows.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// Errors the callers distinguish.
var (
	// ErrNotFound is returned for a row that does not exist and, identically,
	// for a row that exists but belongs to someone else. The two must be
	// indistinguishable: a 403 where a 404 belongs confirms the resource is
	// real, which is a working cross-tenant enumeration oracle (§8.1).
	ErrNotFound = errors.New("not found")

	// ErrDuplicate means the provider redelivered something already held.
	// It is not a failure — it is deduplication working — and the receiver
	// answers the provider 200 on it.
	ErrDuplicate = errors.New("already recorded")

	ErrConflict = errors.New("conflicting concurrent update")
)

// Store is the whole persistence surface.
type Store interface {
	Tenants
	Endpoints
	Destinations
	RawEvents
	CanonicalEvents
	Deliveries
	Audit

	// Health reports whether the store can be written to. The receiver's
	// readiness probe is exactly this and nothing else (§11.1): it must not
	// depend on the dispatcher, or a dispatcher fault takes the receiver out
	// of rotation and loses the events the design exists to protect.
	Health(ctx context.Context) error

	Close() error
}

// Tenants manages customers.
type Tenants interface {
	CreateTenant(ctx context.Context, t domain.Tenant) error
	GetTenant(ctx context.Context, tenantID string) (domain.Tenant, error)
	GetTenantBySlug(ctx context.Context, slug string) (domain.Tenant, error)
	ListTenants(ctx context.Context) ([]domain.Tenant, error)
}

// Endpoints manages receiver URLs.
type Endpoints interface {
	CreateEndpoint(ctx context.Context, e domain.Endpoint) error
	GetEndpoint(ctx context.Context, tenantID, endpointID string) (domain.Endpoint, error)
	ListEndpoints(ctx context.Context, tenantID string) ([]domain.Endpoint, error)
	UpdateEndpoint(ctx context.Context, tenantID string, e domain.Endpoint) error
	DeleteEndpoint(ctx context.Context, tenantID, endpointID string) error

	// ResolveReceiver is the receiver's hot path and the one lookup that is
	// not tenant-scoped, because the tenant is what it resolves. It takes the
	// whole URL tuple rather than the token alone so that a token valid for
	// one provider cannot be replayed against another provider's endpoint.
	ResolveReceiver(ctx context.Context, tenantSlug, provider, env, token string) (domain.Endpoint, domain.Tenant, error)
}

// Destinations manages forwarding targets.
type Destinations interface {
	CreateDestination(ctx context.Context, d domain.Destination) error
	GetDestination(ctx context.Context, tenantID, destinationID string) (domain.Destination, error)
	ListDestinations(ctx context.Context, tenantID string) ([]domain.Destination, error)
	UpdateDestination(ctx context.Context, tenantID string, d domain.Destination) error
	DeleteDestination(ctx context.Context, tenantID, destinationID string) error
}

// RawEvents stores provider bytes.
type RawEvents interface {
	// PutRawEvent is the single write on the receiver's critical path. It has
	// to be durable before it returns, because the 200 that follows tells the
	// provider it may forget the event.
	PutRawEvent(ctx context.Context, e domain.RawEvent) error

	GetRawEvent(ctx context.Context, tenantID, rawEventID string) (domain.RawEvent, error)

	// ListUnnormalised returns raw events with no canonical counterpart, so
	// the normaliser can pick up work left behind by a restart. Recovery
	// depends on a query rather than on an in-memory queue for exactly that
	// reason.
	ListUnnormalised(ctx context.Context, limit int) ([]domain.RawEvent, error)

	// ListSignatureFailures backs the per-endpoint signature-failure view and
	// the forgery alert (§10.1).
	ListSignatureFailures(ctx context.Context, tenantID, endpointID string, since time.Time, limit int) ([]domain.RawEvent, error)
}

// EventQuery is the event explorer's search (§3.2 D1).
type EventQuery struct {
	Provider        string
	Status          domain.Status
	EventType       domain.EventType
	TransactionRef  string
	MappingComplete *bool
	From, To        time.Time

	// Cursor is the last ID of the previous page. Keyset pagination, not
	// OFFSET: the events table is the largest in the system and OFFSET 50000
	// makes the database read fifty thousand rows to discard them.
	Cursor string
	Limit  int
}

// CanonicalEvents stores normalised events.
type CanonicalEvents interface {
	// PutCanonicalEvent returns ErrDuplicate when (tenant, provider,
	// provider_event_id) is already held, which is provider-level dedupe
	// enforced by the database rather than by a check-then-write race.
	PutCanonicalEvent(ctx context.Context, e domain.CanonicalEvent) error

	GetCanonicalEvent(ctx context.Context, tenantID, eventID string) (domain.CanonicalEvent, error)
	GetCanonicalEventByDedupeKey(ctx context.Context, tenantID, provider, providerEventID string) (domain.CanonicalEvent, error)
	QueryEvents(ctx context.Context, tenantID string, q EventQuery) ([]domain.CanonicalEvent, error)

	// MarkNormalisationFailure records that an adapter could not parse a raw
	// event, with the reason. The raw event stays exactly where it is: the
	// whole point of persist-then-acknowledge is that a parse failure costs
	// nothing but a retry against a corrected adapter (ADR-001).
	MarkNormalisationFailure(ctx context.Context, tenantID, rawEventID, reason string) error

	// UnknownStatuses backs the "provider values awaiting mapping" view and
	// the metric that is, quietly, the most useful signal in the product
	// (§11.2).
	UnknownStatuses(ctx context.Context, tenantID string, since time.Time) ([]UnknownStatus, error)
}

// UnknownStatus is one provider status value StatusHub has seen and cannot
// map, with enough context to fix the adapter.
type UnknownStatus struct {
	Provider    string    `json:"provider"`
	RawValue    string    `json:"raw_value"`
	Count       int64     `json:"count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	SampleEvent string    `json:"sample_event_id"`
}

// DeliveryQuery filters the delivery log and the dead-letter view.
type DeliveryQuery struct {
	DestinationID string
	Status        domain.DeliveryStatus
	EventID       string
	From, To      time.Time
	Cursor        int64
	Limit         int
}

// Deliveries stores forwarding attempts.
type Deliveries interface {
	EnqueueDelivery(ctx context.Context, d domain.Delivery) (int64, error)

	// ClaimDue leases deliveries that are due, so several dispatcher
	// replicas can run without two of them delivering the same event.
	// It returns at most one delivery per (shard, transaction reference):
	// that is where per-transaction ordering is actually enforced (§4.5).
	ClaimDue(ctx context.Context, shard int, now time.Time, limit int, lease time.Duration) ([]domain.Delivery, error)

	CompleteDelivery(ctx context.Context, d domain.Delivery) error
	GetDelivery(ctx context.Context, tenantID string, id int64) (domain.Delivery, error)
	ListDeliveriesForEvent(ctx context.Context, tenantID, eventID string) ([]domain.Delivery, error)
	QueryDeliveries(ctx context.Context, tenantID string, q DeliveryQuery) ([]domain.Delivery, error)

	// NextSequence allocates the ordering position for a transaction
	// reference. Allocated at enqueue rather than at delivery so a retried
	// attempt cannot be overtaken by an event queued after it.
	NextSequence(ctx context.Context, tenantID, transactionRef string) (int64, error)

	// QueueDepth and OldestPending back the scaling signal and the
	// head-of-line-blocking alert (§11.4).
	QueueDepth(ctx context.Context) (map[int]int64, error)
	OldestPending(ctx context.Context) (map[int]time.Time, error)
}

// Audit is the append-only trail (§8.3).
type Audit interface {
	// AppendAudit writes one record, chaining it to the tenant's previous
	// record's hash. There is deliberately no update and no delete: the
	// application's database role is not granted them, and a trigger refuses
	// them even for a superuser.
	AppendAudit(ctx context.Context, r domain.AuditRecord) error

	ListAudit(ctx context.Context, tenantID string, since time.Time, limit int) ([]domain.AuditRecord, error)

	// VerifyChain walks a tenant's records and reports the first break.
	VerifyChain(ctx context.Context, tenantID string) (domain.ChainProof, error)

	LastAuditHash(ctx context.Context, tenantID string) (string, error)
}
