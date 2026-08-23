package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapters"
	"github.com/nobledeveloper01/StatusHub/internal/auth"
	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/metrics"
	"github.com/nobledeveloper01/StatusHub/internal/secret"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

// Server is the management API.
type Server struct {
	store      store.Store
	keys       auth.KeyStore
	registry   *adapters.Registry
	dispatcher *dispatch.Dispatcher
	secrets    secret.Resolver
	guard      *dispatch.Guard
	metrics    *metrics.Registry
	log        *slog.Logger
	now        func() time.Time

	// adapterStore holds uploaded declarative adapters per tenant.
	adapterStore AdapterStore

	// idempotency remembers completed writes so a retry returns the original
	// result rather than creating a second resource (§8.6).
	idempotency IdempotencyStore

	// baseURL is where providers POST. Configurable because a self-hosted
	// install is not at hooks.statushub.dev, and a receiver URL that names
	// the wrong host is a URL nobody can use.
	baseURL string
}

// Options configure a Server.
type Options struct {
	Store        store.Store
	Keys         auth.KeyStore
	Registry     *adapters.Registry
	Dispatcher   *dispatch.Dispatcher
	Secrets      secret.Resolver
	Guard        *dispatch.Guard
	Metrics      *metrics.Registry
	Logger       *slog.Logger
	AdapterStore AdapterStore
	Idempotency  IdempotencyStore
	BaseURL      string
	Now          func() time.Time
}

// New builds a Server.
func New(o Options) *Server {
	s := &Server{
		store: o.Store, keys: o.Keys, registry: o.Registry, dispatcher: o.Dispatcher,
		secrets: o.Secrets, guard: o.Guard, metrics: o.Metrics, log: o.Logger,
		adapterStore: o.AdapterStore, idempotency: o.Idempotency,
		baseURL: o.BaseURL, now: o.Now,
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.metrics == nil {
		s.metrics = metrics.New()
	}
	if s.now == nil {
		s.now = func() time.Time { return time.Now().UTC() }
	}
	if s.adapterStore == nil {
		s.adapterStore = NewMemoryAdapterStore()
	}
	if s.idempotency == nil {
		s.idempotency = NewMemoryIdempotencyStore()
	}
	return s
}

// Handler returns the routed, middlewared management API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated. Health says the process is alive; readiness says it
	// can do its job. They are separate because a readiness failure should
	// remove an instance from rotation and a health failure should restart it
	// — conflating them turns a slow database into a restart loop.
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	authed := http.NewServeMux()

	// Endpoints — the receiver URLs providers are pointed at.
	authed.HandleFunc("POST /v1/endpoints", requireRole(auth.RoleEngineer, s.idempotent(s.handleCreateEndpoint)))
	authed.HandleFunc("GET /v1/endpoints", requireRole(auth.RoleReadOnly, s.handleListEndpoints))
	authed.HandleFunc("GET /v1/endpoints/{id}", requireRole(auth.RoleReadOnly, s.handleGetEndpoint))
	authed.HandleFunc("DELETE /v1/endpoints/{id}", requireRole(auth.RoleEngineer, s.handleDeleteEndpoint))
	authed.HandleFunc("POST /v1/endpoints/{id}/rotate-token", requireRole(auth.RoleEngineer, s.idempotent(s.handleRotateToken)))
	authed.HandleFunc("GET /v1/endpoints/{id}/signature-failures", requireRole(auth.RoleSupport, s.handleSignatureFailures))

	// Destinations — where events are forwarded.
	authed.HandleFunc("POST /v1/destinations", requireRole(auth.RoleEngineer, s.idempotent(s.handleCreateDestination)))
	authed.HandleFunc("GET /v1/destinations", requireRole(auth.RoleReadOnly, s.handleListDestinations))
	authed.HandleFunc("GET /v1/destinations/{id}", requireRole(auth.RoleReadOnly, s.handleGetDestination))
	authed.HandleFunc("DELETE /v1/destinations/{id}", requireRole(auth.RoleEngineer, s.handleDeleteDestination))

	// Adapters.
	authed.HandleFunc("GET /v1/adapters", requireRole(auth.RoleReadOnly, s.handleListAdapters))
	authed.HandleFunc("POST /v1/adapters", requireRole(auth.RoleEngineer, s.idempotent(s.handleUploadAdapter)))
	authed.HandleFunc("POST /v1/adapters/{name}/test", requireRole(auth.RoleEngineer, s.handleTestAdapter))
	authed.HandleFunc("DELETE /v1/adapters/{name}", requireRole(auth.RoleEngineer, s.handleDeleteAdapter))

	// Events — the explorer's whole surface.
	authed.HandleFunc("GET /v1/events", requireRole(auth.RoleReadOnly, s.handleQueryEvents))
	authed.HandleFunc("GET /v1/events/{id}", requireRole(auth.RoleReadOnly, s.handleGetEvent))
	authed.HandleFunc("GET /v1/events/{id}/raw", requireRole(auth.RoleSupport, s.handleGetRawPayload))
	authed.HandleFunc("POST /v1/events/{id}/replay", requireRole(auth.RoleSupport, s.idempotent(s.handleReplayEvent)))
	authed.HandleFunc("POST /v1/events/replay", requireRole(auth.RoleSupport, s.idempotent(s.handleBulkReplay)))

	// Deliveries and dead letters.
	authed.HandleFunc("GET /v1/deliveries", requireRole(auth.RoleReadOnly, s.handleQueryDeliveries))
	authed.HandleFunc("POST /v1/deliveries/{id}/retry", requireRole(auth.RoleSupport, s.idempotent(s.handleRetryDelivery)))

	// The to-do list the product generates for itself.
	authed.HandleFunc("GET /v1/unknown-statuses", requireRole(auth.RoleReadOnly, s.handleUnknownStatuses))

	// Audit.
	authed.HandleFunc("GET /v1/audit", requireRole(auth.RoleReadOnly, s.handleListAudit))
	authed.HandleFunc("GET /v1/audit/verify", requireRole(auth.RoleReadOnly, s.handleVerifyAudit))

	// Keys. Owner only: a key that can issue keys is a key that can escalate.
	authed.HandleFunc("POST /v1/keys", requireRole(auth.RoleOwner, s.idempotent(s.handleCreateKey)))
	authed.HandleFunc("GET /v1/keys", requireRole(auth.RoleOwner, s.handleListKeys))
	authed.HandleFunc("DELETE /v1/keys/{id}", requireRole(auth.RoleOwner, s.handleRevokeKey))

	mux.Handle("/v1/", s.authenticate(authed))
	return securityHeaders(s.recoverPanic(mux))
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Health(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "unavailable", "detail": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if err := s.metrics.Write(w); err != nil {
		s.log.Error("could not write metrics", "error", err)
	}
}

// audit appends a record, logging rather than failing when it cannot.
//
// A management write that has already happened must not be reported as failed
// because its audit record could not be written — the caller would retry and
// do it twice. The gap is logged at error because a hole in the trail is a
// compliance finding, and the nightly chain walk will surface it too.
func (s *Server) audit(ctx context.Context, id auth.Identity, eventType domain.AuditEventType, subject domain.Subject, payload map[string]any) {
	rec := domain.AuditRecord{
		TenantID:  id.TenantID,
		EventType: eventType,
		Actor:     id.Actor(),
		Subject:   subject,
		Payload:   payload,
	}
	if err := s.store.AppendAudit(ctx, rec); err != nil {
		s.log.ErrorContext(ctx, "audit append failed",
			"tenant", id.TenantID, "event_type", eventType, "error", err)
	}
}
