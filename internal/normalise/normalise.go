// Package normalise turns stored provider bytes into canonical events.
//
// It runs entirely off the request path. The provider was answered before
// this package was involved, which is what makes every failure in here
// recoverable: the raw bytes are already durable, so a mapping that is wrong
// today is fixed by correcting the adapter and replaying, not by asking the
// provider to resend something they have long since forgotten (ADR-001).
package normalise

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapters"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/metrics"
	"github.com/nobledeveloper01/StatusHub/internal/secret"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

// Enqueuer is handed each newly normalised event so it can be queued for
// delivery. It is an interface so the normaliser has no dependency on the
// dispatcher: the two are separate workloads and one must be able to run
// without the other (§11.1).
type Enqueuer interface {
	Enqueue(ctx context.Context, e domain.CanonicalEvent) error
}

// Normaliser maps raw events onto the canonical schema.
type Normaliser struct {
	store    store.Store
	registry *adapters.Registry
	secrets  secret.Resolver
	metrics  *metrics.Registry
	log      *slog.Logger
	enqueue  Enqueuer
	now      func() time.Time
}

// Options configure a Normaliser.
type Options struct {
	Store    store.Store
	Registry *adapters.Registry
	Secrets  secret.Resolver
	Metrics  *metrics.Registry
	Logger   *slog.Logger
	Enqueuer Enqueuer
	Now      func() time.Time
}

// New builds a Normaliser.
func New(o Options) *Normaliser {
	n := &Normaliser{
		store:    o.Store,
		registry: o.Registry,
		secrets:  o.Secrets,
		metrics:  o.Metrics,
		log:      o.Logger,
		enqueue:  o.Enqueuer,
		now:      o.Now,
	}
	if n.log == nil {
		n.log = slog.Default()
	}
	if n.metrics == nil {
		n.metrics = metrics.New()
	}
	if n.now == nil {
		n.now = func() time.Time { return time.Now().UTC() }
	}
	return n
}

// ErrNotNormalisable means the raw event will never parse, however many times
// it is retried. It is distinguished from a transient failure because the two
// need opposite handling: a transient failure should be retried and a
// permanent one should stop consuming attempts and appear on the operator's
// list instead.
var ErrNotNormalisable = errors.New("raw event cannot be normalised")

// Process normalises one raw event.
//
// It is safe to call twice for the same event: the duplicate is recognised
// and reported without a second canonical event being created, which matters
// because a crash between writing the event and marking the raw one done is
// an ordinary occurrence rather than an exotic one.
func (n *Normaliser) Process(ctx context.Context, rawEventID, tenantID string) error {
	start := n.now()

	raw, err := n.store.GetRawEvent(ctx, tenantID, rawEventID)
	if err != nil {
		return fmt.Errorf("fetching raw event %s: %w", rawEventID, err)
	}

	// A forgery is stored as evidence and never normalised, because
	// normalising it is the first step towards forwarding it (§10.1).
	if !raw.SignatureValid {
		return fmt.Errorf("%w: signature was not valid, so it is retained as evidence and never forwarded", ErrNotNormalisable)
	}

	endpoint, err := n.store.GetEndpoint(ctx, tenantID, raw.EndpointID)
	if err != nil {
		return fmt.Errorf("fetching endpoint %s: %w", raw.EndpointID, err)
	}

	a, err := n.registry.Get(tenantID, endpoint.AdapterName)
	if err != nil {
		// Transient rather than permanent: an adapter can be uploaded or a
		// release can add one, and marking the event permanently failed would
		// mean it is never picked up when that happens.
		return fmt.Errorf("adapter %q unavailable: %w", endpoint.AdapterName, err)
	}

	ev, err := a.Parse(raw.Body)
	if err != nil {
		n.metrics.Inc("statushub_normalisation_failures_total", metrics.Labels{
			"provider": raw.Provider, "reason": reasonFor(err),
		})
		// Recorded against the raw event, which stays exactly where it is.
		// This is runbook 11.5: correct the adapter, then replay the window.
		if merr := n.store.MarkNormalisationFailure(ctx, tenantID, rawEventID, err.Error()); merr != nil {
			n.log.ErrorContext(ctx, "could not record a normalisation failure",
				"raw_event", rawEventID, "error", merr)
		}
		n.log.WarnContext(ctx, "adapter could not parse a provider payload",
			"provider", raw.Provider, "tenant", tenantID, "raw_event", rawEventID,
			"adapter", endpoint.AdapterName, "error", err)
		return fmt.Errorf("%w: %w", ErrNotNormalisable, err)
	}

	ev.ID = domain.NewID(domain.PrefixEvent)
	ev.TenantID = tenantID
	ev.RawEventID = raw.ID
	ev.Provider = endpoint.Provider
	ev.ReceivedAt = raw.ReceivedAt
	ev.NormalisedAt = n.now()
	if ev.OccurredAt.IsZero() {
		// A provider that sent no usable timestamp gets our receipt time,
		// flagged. Leaving it zero would sort the event to the beginning of
		// time in every ordered view.
		ev.OccurredAt = raw.ReceivedAt
		ev.MappingComplete = false
	}

	// The adapter put an identifier — an email, an account name — in
	// CustomerRefHash. It is hashed here, with the tenant's own salt, and the
	// plaintext is discarded. The adapter never sees the salt, so no adapter
	// can accidentally write an identifier in the clear (§8.4).
	if ev.CustomerRefHash != "" {
		hashed, herr := n.pseudonymise(ctx, tenantID, ev.CustomerRefHash)
		if herr != nil {
			// Without a salt the only safe act is to drop the identifier.
			// Storing it unhashed would be a data-protection failure caused
			// by a configuration problem, which is the worst way to acquire
			// one.
			n.log.ErrorContext(ctx, "customer reference dropped: the tenant salt did not resolve",
				"tenant", tenantID, "error", herr)
			ev.CustomerRefHash = ""
			ev.MappingComplete = false
		} else {
			ev.CustomerRefHash = hashed
		}
	}

	if ev.Redacted = raw.Redacted; ev.Redacted {
		ev.ProviderExtra["statushub_redacted"] = raw.RedactionNote
	}

	ev.Normalise()
	if err := ev.Validate(); err != nil {
		n.metrics.Inc("statushub_normalisation_failures_total", metrics.Labels{
			"provider": raw.Provider, "reason": "invalid_canonical_event",
		})
		if merr := n.store.MarkNormalisationFailure(ctx, tenantID, rawEventID, err.Error()); merr != nil {
			n.log.ErrorContext(ctx, "could not record a validation failure", "raw_event", rawEventID, "error", merr)
		}
		// A broken adapter, not a broken payload. It is worth an error rather
		// than a warning because it means code we shipped is producing rows
		// that violate the schema everything downstream trusts.
		n.log.ErrorContext(ctx, "adapter produced an invalid canonical event",
			"provider", raw.Provider, "adapter", endpoint.AdapterName, "raw_event", rawEventID, "error", err)
		return fmt.Errorf("%w: %w", ErrNotNormalisable, err)
	}

	n.recordMappingQuality(ev)

	if err := n.store.PutCanonicalEvent(ctx, ev); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			// The provider redelivered something already held. Not a failure
			// — deduplication working — and the raw event is still marked
			// done so it stops being picked up.
			n.metrics.Inc("statushub_duplicates_rejected_total", metrics.Labels{"provider": raw.Provider})
			n.log.InfoContext(ctx, "provider redelivered an event already held",
				"provider", raw.Provider, "tenant", tenantID,
				"provider_event_id", ev.ProviderEventID, "raw_event", rawEventID)
			if merr := n.store.MarkNormalisationFailure(ctx, tenantID, rawEventID,
				"duplicate of an event already normalised"); merr != nil {
				n.log.ErrorContext(ctx, "could not mark a duplicate", "raw_event", rawEventID, "error", merr)
			}
			return nil
		}
		return fmt.Errorf("storing canonical event: %w", err)
	}

	n.metrics.Observe("statushub_normalisation_duration_seconds",
		metrics.Labels{"provider": raw.Provider}, n.now().Sub(start))

	n.audit(ctx, domain.AuditRecord{
		TenantID:  tenantID,
		EventType: domain.AuditEventNormalised,
		Actor:     domain.Actor{Type: domain.ActorSystem},
		Subject:   domain.Subject{Type: "event", ID: ev.ID},
		Payload: map[string]any{
			"raw_event":        raw.ID,
			"provider":         ev.Provider,
			"adapter":          endpoint.AdapterName,
			"transaction_ref":  ev.TransactionRef,
			"status":           ev.Status.String(),
			"mapping_complete": ev.MappingComplete,
		},
	})

	if n.enqueue != nil {
		if err := n.enqueue.Enqueue(ctx, ev); err != nil {
			// The event is stored. A delivery that was not queued is
			// recovered by the dispatcher's own sweep for events with no
			// deliveries, so this is logged and not returned — returning it
			// would re-run normalisation and hit the duplicate path.
			n.log.ErrorContext(ctx, "could not queue an event for delivery",
				"event", ev.ID, "tenant", tenantID, "error", err)
		}
	}
	return nil
}

// recordMappingQuality emits the two metrics that tell the team what to build
// next (§11.2).
func (n *Normaliser) recordMappingQuality(ev domain.CanonicalEvent) {
	if ev.UnmappedStatus != "" {
		// The most valuable series in the system: a live feed of exactly
		// which provider status values have no mapping yet.
		n.metrics.Inc("statushub_status_unknown_total", metrics.Labels{
			"provider": ev.Provider, "raw_value": ev.UnmappedStatus,
		})
	}
	if !ev.MappingComplete {
		n.metrics.Inc("statushub_mapping_incomplete_total", metrics.Labels{
			"provider": ev.Provider, "event_type": ev.EventType.String(),
		})
	}
}

// pseudonymise hashes a customer identifier with the tenant's salt.
//
// HMAC rather than a plain hash, and per-tenant rather than global. A plain
// SHA-256 of an email address is reversible with a wordlist in seconds, and a
// global salt would let anyone holding one tenant's data correlate a person
// across every other tenant. Neither is acceptable for the field whose whole
// purpose is to let us correlate without holding who the person is.
func (n *Normaliser) pseudonymise(ctx context.Context, tenantID, value string) (string, error) {
	salt, err := n.secrets.Resolve(ctx, saltRef(tenantID))
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, []byte(salt))
	_, _ = m.Write([]byte(value))
	return "sha256:" + hex.EncodeToString(m.Sum(nil)), nil
}

// SaltRef returns the secret reference holding a tenant's pseudonymisation
// salt. Exported so provisioning and the erasure tooling name it the same
// way; a mismatch here would silently produce hashes nothing can match.
func SaltRef(tenantID string) string { return saltRef(tenantID) }

func saltRef(tenantID string) string { return "tenant-salt://" + tenantID }

// reasonFor maps a parse error to a bounded metric label. The error text
// itself can contain provider-controlled content, and a metric label an
// attacker can influence is an unbounded cardinality problem.
func reasonFor(err error) string {
	switch {
	case errors.Is(err, errNoTransaction):
		return "no_transaction_ref"
	case errors.Is(err, errUnparseable):
		return "unparseable"
	default:
		return "other"
	}
}

func (n *Normaliser) audit(ctx context.Context, rec domain.AuditRecord) {
	if err := n.store.AppendAudit(ctx, rec); err != nil {
		n.log.ErrorContext(ctx, "audit append failed",
			"tenant", rec.TenantID, "event_type", rec.EventType, "error", err)
	}
}
