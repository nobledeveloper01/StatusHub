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
	"github.com/nobledeveloper01/StatusHub/internal/tunnel"
	webembed "github.com/nobledeveloper01/StatusHub/web/embed"
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

	// tunnel streams live events to a developer's machine. Nil when this
	// instance does not accept listen sessions.
	tunnel *tunnel.Hub

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
	Tunnel       *tunnel.Hub
	Idempotency  IdempotencyStore
	BaseURL      string
	Now          func() time.Time
}

// New builds a Server.
func New(o Options) *Server {
	s := &Server{
		store: o.Store, keys: o.Keys, registry: o.Registry, dispatcher: o.Dispatcher,
		secrets: o.Secrets, guard: o.Guard, metrics: o.Metrics, log: o.Logger,
		adapterStore: o.AdapterStore, tunnel: o.Tunnel, idempotency: o.Idempotency,
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
//
// Built from the same route table the OpenAPI document is generated from, so
// a route cannot exist in one and not the other.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	authed := http.NewServeMux()

	for _, r := range routes {
		h := r.handler(s)

		if r.Public {
			mux.HandleFunc(r.Method+" "+r.Path, h)
			continue
		}
		if r.Idempotent {
			h = s.idempotent(h)
		}
		authed.HandleFunc(r.Method+" "+r.Path, requireRole(r.Role, h))
	}

	mux.Handle("/v1/", s.authenticate(authed))

	// The dashboard is served from the same origin as the API, so the browser
	// needs no CORS grant and the API needs no cross-origin allowance — which
	// is one fewer thing to get subtly wrong on a management surface.
	//
	// It is served unauthenticated because it is static HTML and JavaScript
	// containing nothing: every byte of data it displays comes from the
	// authenticated routes above, and gating the assets would only mean a
	// login page that cannot render.
	mux.Handle("/", dashboardHandler())

	return securityHeaders(s.recoverPanic(mux))
}

// dashboardHandler serves the embedded dashboard.
func dashboardHandler() http.Handler {
	files := http.FileServer(http.FS(webembed.FS()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A same-origin-only content security policy. The dashboard loads no
		// external anything on purpose: a fintech's webhook console should not
		// tell a CDN when its operations team is looking at an incident, and
		// should not stop working when that CDN does.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; "+
				"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		files.ServeHTTP(w, r)
	})
}

func (s *Server) handleSchemaVersions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"versions": dispatch.SchemaVersions(),
		"latest":   string(dispatch.SchemaLatest),
		"note": "A destination keeps the version it was created with. Moving to a newer one is a change " +
			"you make on a day you chose; a version is never retired without a dated notice.",
	})
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
