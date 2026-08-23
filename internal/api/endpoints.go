package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/auth"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

type endpointView struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	Environment string `json:"environment"`
	AdapterName string `json:"adapter"`
	Enabled     bool   `json:"enabled"`

	// ReceiverURL is the whole point of the resource: the one thing the
	// customer pastes into a provider's dashboard.
	ReceiverURL string `json:"receiver_url"`

	// SecretRef is a reference, never a secret. A management API that could
	// return a signing secret would make every API key as dangerous as the
	// secret itself.
	SecretRef string `json:"secret_ref"`

	AllowedSourceCIDRs []string `json:"allowed_source_cidrs,omitempty"`

	// Warning carries the adapter's own statement of a weaker guarantee, so a
	// customer sees it on the resource rather than having to go and read
	// about their provider's signature scheme.
	Warning string `json:"warning,omitempty"`

	CreatedAt time.Time  `json:"created_at"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
}

func (s *Server) viewEndpoint(e domain.Endpoint, slug, baseURL string) endpointView {
	v := endpointView{
		ID: e.ID, Provider: e.Provider, Environment: e.Environment.String(),
		AdapterName: e.AdapterName, Enabled: e.Enabled,
		ReceiverURL: strings.TrimRight(baseURL, "/") + e.ReceiverPath(slug),
		SecretRef:   e.SecretRef, AllowedSourceCIDRs: e.AllowedSourceCIDRs,
		CreatedAt: e.CreatedAt,
	}
	if !e.RotatedAt.IsZero() {
		t := e.RotatedAt
		v.RotatedAt = &t
	}
	if a, err := s.registry.Get(e.TenantID, e.AdapterName); err == nil {
		if sr, ok := a.(interface{ WhySourceCheckIsWeaker() string }); ok {
			v.Warning = sr.WhySourceCheckIsWeaker()
		}
	}
	return v
}

type createEndpointRequest struct {
	Provider           string   `json:"provider"`
	Environment        string   `json:"environment"`
	Adapter            string   `json:"adapter,omitempty"`
	SecretRef          string   `json:"secret_ref"`
	AllowedSourceCIDRs []string `json:"allowed_source_cidrs,omitempty"`
}

func (s *Server) handleCreateEndpoint(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}

	var req createEndpointRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "request body: "+err.Error())
		return
	}

	env, ok := parseEnvironment(req.Environment)
	if !ok {
		writeError(w, http.StatusBadRequest, "environment must be test or live")
		return
	}
	// A key issued for test must not be able to create a live endpoint. This
	// is the same scoping rule as everywhere else, applied at the point where
	// it would otherwise be easy to forget.
	if id.Environment != env {
		writeError(w, http.StatusForbidden,
			"this key is scoped to the "+id.Environment.String()+" environment")
		return
	}

	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if provider == "" {
		writeError(w, http.StatusBadRequest, "provider is required")
		return
	}
	adapterName := req.Adapter
	if adapterName == "" {
		adapterName = provider
	}
	if _, err := s.registry.Get(id.TenantID, adapterName); err != nil {
		writeError(w, http.StatusBadRequest,
			"no adapter named "+adapterName+"; upload a declarative adapter or use a built-in one")
		return
	}
	if strings.TrimSpace(req.SecretRef) == "" {
		writeError(w, http.StatusBadRequest,
			"secret_ref is required: StatusHub stores a reference to the provider's signing secret, never the secret")
		return
	}
	// Resolved now rather than at the first webhook. A reference that does
	// not resolve produces an endpoint that silently rejects every event as
	// unverified, which looks identical to an attack.
	if _, err := s.secrets.Resolve(r.Context(), req.SecretRef); err != nil {
		writeError(w, http.StatusBadRequest, "secret_ref does not resolve: "+err.Error())
		return
	}

	ep := domain.Endpoint{
		ID:                 domain.NewID(domain.PrefixEndpoint),
		TenantID:           id.TenantID,
		Provider:           provider,
		Environment:        env,
		ReceiverToken:      domain.NewToken(),
		SecretRef:          req.SecretRef,
		AdapterName:        adapterName,
		AllowedSourceCIDRs: req.AllowedSourceCIDRs,
		Enabled:            true,
		CreatedAt:          s.now(),
	}
	if err := s.store.CreateEndpoint(r.Context(), ep); err != nil {
		writeStoreError(w, err)
		return
	}

	s.audit(r.Context(), id, domain.AuditEndpointCreated,
		domain.Subject{Type: "endpoint", ID: ep.ID},
		map[string]any{"provider": provider, "environment": env.String(), "adapter": adapterName})

	writeJSON(w, http.StatusCreated, s.viewEndpoint(ep, id.TenantSlug, s.receiverBaseURL()))
}

func (s *Server) handleListEndpoints(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	eps, err := s.store.ListEndpoints(r.Context(), id.TenantID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := make([]endpointView, 0, len(eps))
	for _, e := range eps {
		out = append(out, s.viewEndpoint(e, id.TenantSlug, s.receiverBaseURL()))
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": out})
}

func (s *Server) handleGetEndpoint(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	ep, err := s.store.GetEndpoint(r.Context(), id.TenantID, r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.viewEndpoint(ep, id.TenantSlug, s.receiverBaseURL()))
}

func (s *Server) handleDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	epID := r.PathValue("id")
	if err := s.store.DeleteEndpoint(r.Context(), id.TenantID, epID); err != nil {
		writeStoreError(w, err)
		return
	}
	// The raw events stay. Deleting an endpoint removes the URL, not the
	// history — the events it received are still the evidence of what the
	// provider reported and when (§9).
	s.audit(r.Context(), id, domain.AuditEndpointDeleted,
		domain.Subject{Type: "endpoint", ID: epID}, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleRotateToken issues a new receiver token for an endpoint.
//
// The URL structure does not change, only the token in it — so rotating is a
// one-line edit in the provider's dashboard rather than a reconfiguration
// (§10). The old token stops working immediately, which is the point: a token
// is rotated because it leaked.
func (s *Server) handleRotateToken(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	ep, err := s.store.GetEndpoint(r.Context(), id.TenantID, r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}

	previous := ep.ReceiverToken
	ep.ReceiverToken = domain.NewToken()
	ep.RotatedAt = s.now()
	if err := s.store.UpdateEndpoint(r.Context(), id.TenantID, ep); err != nil {
		writeStoreError(w, err)
		return
	}

	s.audit(r.Context(), id, domain.AuditTokenRotated,
		domain.Subject{Type: "endpoint", ID: ep.ID},
		// The previous token is not recorded, even in the audit trail. It is
		// still a URL component that would work if the rotation were rolled
		// back, and an audit log is read by more people than a secret store.
		map[string]any{"provider": ep.Provider, "previous_token_length": len(previous)})

	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint": s.viewEndpoint(ep, id.TenantSlug, s.receiverBaseURL()),
		"note":     "update this URL in the provider's dashboard now; the previous token stopped working immediately",
	})
}

// handleSignatureFailures backs the forgery view (§10.1).
func (s *Server) handleSignatureFailures(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	epID := r.PathValue("id")
	if _, err := s.store.GetEndpoint(r.Context(), id.TenantID, epID); err != nil {
		writeStoreError(w, err)
		return
	}

	since := s.now().Add(-24 * time.Hour)
	if t, ok := parseTime(r.URL.Query().Get("since")); ok {
		since = t
	}
	failures, err := s.store.ListSignatureFailures(r.Context(), id.TenantID, epID, since, 200)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	type view struct {
		RawEventID string    `json:"raw_event_id"`
		SourceIP   string    `json:"source_ip"`
		Reason     string    `json:"reason"`
		ReceivedAt time.Time `json:"received_at"`
		Bytes      int       `json:"bytes"`
	}
	out := make([]view, 0, len(failures))
	for _, f := range failures {
		out = append(out, view{
			RawEventID: f.ID, SourceIP: f.SourceIP.String(),
			// The operator sees exactly why. The caller who sent it never
			// does (§7.1).
			Reason: f.SignatureError, ReceivedAt: f.ReceivedAt, Bytes: len(f.Body),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint": epID, "since": since, "failures": out,
		"note": "these events were stored and flagged, and were never forwarded to any destination",
	})
}

// receiverBaseURL is where providers POST. Configurable because a self-hosted
// install is not at hooks.statushub.dev.
func (s *Server) receiverBaseURL() string {
	if s.baseURL != "" {
		return s.baseURL
	}
	return "https://hooks.statushub.dev"
}
