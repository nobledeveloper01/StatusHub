package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/auth"
	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

type destinationView struct {
	ID                 string        `json:"id"`
	Name               string        `json:"name,omitempty"`
	URL                string        `json:"url"`
	SigningSecretRef   string        `json:"signing_secret_ref"`
	Filter             domain.Filter `json:"filter"`
	RetryScheduleHuman []string      `json:"retry_schedule"`
	IncludeRaw         bool          `json:"include_raw"`
	SchemaVersion      string        `json:"schema_version"`
	Enabled            bool          `json:"enabled"`
	CreatedAt          time.Time     `json:"created_at"`
}

func viewDestination(d domain.Destination) destinationView {
	policy := d.RetryPolicy
	if len(policy.Backoff) == 0 {
		policy = domain.DefaultRetryPolicy()
	}
	// Rendered as human durations rather than nanoseconds. A customer plans
	// their on-call around this schedule, so it has to be readable at a
	// glance rather than converted in someone's head.
	schedule := make([]string, 0, len(policy.Backoff))
	for _, b := range policy.Backoff {
		schedule = append(schedule, b.String())
	}
	return destinationView{
		ID: d.ID, Name: d.Name, URL: d.URL, SigningSecretRef: d.SigningSecretRef,
		Filter: d.Filter, RetryScheduleHuman: schedule, IncludeRaw: d.IncludeRaw,
		// Resolved rather than echoed, so the response says which shape will
		// actually be delivered rather than which one happens to be stored.
		SchemaVersion: string(dispatch.ResolveSchema(dispatch.SchemaVersion(d.SchemaVersion))),
		Enabled:       d.Enabled, CreatedAt: d.CreatedAt,
	}
}

type createDestinationRequest struct {
	Name             string        `json:"name,omitempty"`
	URL              string        `json:"url"`
	SigningSecretRef string        `json:"signing_secret_ref"`
	Filter           domain.Filter `json:"filter,omitempty"`
	IncludeRaw       bool          `json:"include_raw,omitempty"`

	// SchemaVersion pins the payload shape. Omitted means the newest at
	// creation time, which is safe here because the destination has no
	// existing handler to break.
	SchemaVersion string `json:"schema_version,omitempty"`

	// RetryBackoffSeconds overrides the default schedule. Expressed in
	// seconds rather than as a duration string because it is written by
	// machines more often than by people.
	RetryBackoffSeconds []int `json:"retry_backoff_seconds,omitempty"`
	TimeoutSeconds      int   `json:"timeout_seconds,omitempty"`
}

func (s *Server) handleCreateDestination(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}

	var req createDestinationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "request body: "+err.Error())
		return
	}

	if err := domain.ValidateDestinationURL(req.URL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The registration-time SSRF check. It is necessary and not sufficient —
	// the dialler re-resolves at delivery time, because a hostname that
	// resolves publicly now can resolve to the metadata service by the time
	// the first event arrives (§10).
	if s.guard != nil {
		if err := s.guard.CheckURL(r.Context(), req.URL); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if strings.TrimSpace(req.SigningSecretRef) == "" {
		writeError(w, http.StatusBadRequest, "signing_secret_ref is required")
		return
	}
	if _, err := s.secrets.Resolve(r.Context(), req.SigningSecretRef); err != nil {
		writeError(w, http.StatusBadRequest, "signing_secret_ref does not resolve: "+err.Error())
		return
	}
	schema := dispatch.SchemaVersion(req.SchemaVersion)
	if schema == "" {
		// A brand-new destination gets the newest shape. An existing one
		// never moves on its own — that asymmetry is the whole mechanism.
		schema = dispatch.SchemaLatest
	}
	if !dispatch.ValidSchemaVersion(schema) {
		writeError(w, http.StatusBadRequest,
			"schema_version "+req.SchemaVersion+" is not served; GET /v1/schema-versions lists what is")
		return
	}

	if err := req.Filter.Validate(); err != nil {
		// A filter naming a status that does not exist matches nothing, and a
		// destination that silently receives nothing is the hardest kind of
		// misconfiguration to notice.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	policy := domain.DefaultRetryPolicy()
	if len(req.RetryBackoffSeconds) > 0 {
		policy.Backoff = policy.Backoff[:0]
		for _, s := range req.RetryBackoffSeconds {
			policy.Backoff = append(policy.Backoff, time.Duration(s)*time.Second)
		}
	}
	if req.TimeoutSeconds > 0 {
		policy.Timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	if err := policy.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	dest := domain.Destination{
		ID: domain.NewID(domain.PrefixDestination), TenantID: id.TenantID,
		Name: req.Name, URL: req.URL, SigningSecretRef: req.SigningSecretRef,
		Filter: req.Filter, RetryPolicy: policy, IncludeRaw: req.IncludeRaw,
		SchemaVersion: string(schema), Enabled: true, CreatedAt: s.now(),
	}
	if err := s.store.CreateDestination(r.Context(), dest); err != nil {
		writeStoreError(w, err)
		return
	}

	s.audit(r.Context(), id, domain.AuditDestinationCreated,
		domain.Subject{Type: "destination", ID: dest.ID},
		map[string]any{"url": dest.URL, "include_raw": dest.IncludeRaw,
			"schema_version": dest.SchemaVersion})

	writeJSON(w, http.StatusCreated, viewDestination(dest))
}

func (s *Server) handleListDestinations(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	dests, err := s.store.ListDestinations(r.Context(), id.TenantID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := make([]destinationView, 0, len(dests))
	for _, d := range dests {
		out = append(out, viewDestination(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"destinations": out})
}

func (s *Server) handleGetDestination(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	d, err := s.store.GetDestination(r.Context(), id.TenantID, r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, viewDestination(d))
}

func (s *Server) handleDeleteDestination(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	destID := r.PathValue("id")
	if err := s.store.DeleteDestination(r.Context(), id.TenantID, destID); err != nil {
		writeStoreError(w, err)
		return
	}
	s.audit(r.Context(), id, domain.AuditDestinationDeleted,
		domain.Subject{Type: "destination", ID: destID}, nil)
	w.WriteHeader(http.StatusNoContent)
}
