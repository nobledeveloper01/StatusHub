package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/auth"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/tunnel"
)

// The listen endpoints back `statushubctl listen`, which streams a tenant's
// live events to a developer's laptop.
//
// They are engineer-role rather than read-only: streaming live production
// payloads to an arbitrary machine is a data-egress decision, not a read.

func (s *Server) handleStartListen(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.tunnel == nil {
		writeError(w, http.StatusServiceUnavailable, "this instance does not accept listen sessions")
		return
	}

	var req struct {
		Forward string        `json:"forward,omitempty"`
		Filter  domain.Filter `json:"filter,omitempty"`
	}
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "request body: "+err.Error())
			return
		}
	}
	if err := req.Filter.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	session := s.tunnel.Start(id.TenantID, req.Forward, req.Filter)
	s.audit(r.Context(), id, domain.AuditEventType("listen.started"),
		domain.Subject{Type: "listen_session", ID: session.ID},
		// Recorded, because streaming live payloads to a developer's machine
		// is worth being able to account for afterwards.
		map[string]any{"forward": req.Forward})

	writeJSON(w, http.StatusCreated, map[string]any{
		"session_id":     session.ID,
		"poll_seconds":   int(tunnel.MaxWait.Seconds()),
		"idle_timeout_s": int(tunnel.MaxSessionAge.Seconds()),
		"note": "Events are copied to this session, never diverted from it: your real destinations keep " +
			"receiving everything while you listen.",
	})
}

func (s *Server) handlePollListen(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.tunnel == nil {
		writeError(w, http.StatusServiceUnavailable, "this instance does not accept listen sessions")
		return
	}

	max := 20
	if v := r.URL.Query().Get("max"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			max = n
		}
	}

	deliveries, err := s.tunnel.Poll(r.Context(), id.TenantID, r.PathValue("id"), max)
	switch {
	case errors.Is(err, tunnel.ErrNoSession):
		// Expired rather than forbidden: the developer's laptop slept, and
		// the CLI should start a new session rather than treat this as a
		// permissions problem.
		writeError(w, http.StatusGone, "this listen session has expired; start a new one")
		return
	case err != nil && r.Context().Err() != nil:
		// The client hung up mid-poll, which is the ordinary way a long poll
		// ends when somebody presses Ctrl-C.
		return
	case err != nil:
		writeStoreError(w, err)
		return
	}

	queued, _ := s.tunnel.Queued(id.TenantID, r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]any{
		"deliveries": deliveries,
		// So the CLI can warn a developer whose handler has fallen behind,
		// before events start being dropped from the back of the queue.
		"queued": queued,
	})
}

func (s *Server) handleReportListen(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.tunnel == nil {
		writeError(w, http.StatusServiceUnavailable, "this instance does not accept listen sessions")
		return
	}

	var req struct {
		Outcomes []tunnel.Outcome `json:"outcomes"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "request body: "+err.Error())
		return
	}
	if err := s.tunnel.Report(id.TenantID, r.PathValue("id"), req.Outcomes); err != nil {
		writeError(w, http.StatusGone, "this listen session has expired")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStopListen(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.tunnel != nil {
		s.tunnel.Stop(id.TenantID, r.PathValue("id"))
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListListen(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.tunnel == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sessions": []any{}})
		return
	}

	type view struct {
		ID        string    `json:"id"`
		Forward   string    `json:"forward,omitempty"`
		StartedAt time.Time `json:"started_at"`
		LastSeen  time.Time `json:"last_seen"`
		Delivered int64     `json:"delivered"`
		Failed    int64     `json:"failed"`
	}
	sessions := s.tunnel.Sessions(id.TenantID)
	out := make([]view, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, view{
			ID: sess.ID, Forward: sess.Forward, StartedAt: sess.StartedAt,
			LastSeen: sess.LastSeen, Delivered: sess.Delivered, Failed: sess.Failed,
		})
	}
	// Visible to the whole team, deliberately: an operator should be able to
	// see that somebody's laptop is receiving live production events.
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}
