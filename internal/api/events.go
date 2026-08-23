package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/auth"
	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

// handleQueryEvents is the event explorer's search (§3.2 D1).
//
// The one screen that keeps customers. Everything it can filter on is
// something an engineer types into it during an incident: a transaction
// reference from a customer complaint, a provider that is behaving oddly, or
// mapping_complete=false to see what StatusHub itself is unsure about.
func (s *Server) handleQueryEvents(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	q := r.URL.Query()

	query := store.EventQuery{
		Provider:       strings.TrimSpace(q.Get("provider")),
		TransactionRef: strings.TrimSpace(q.Get("transaction_ref")),
		Cursor:         strings.TrimSpace(q.Get("cursor")),
	}
	if v := q.Get("status"); v != "" {
		st, err := domain.ParseStatus(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		query.Status = st
	}
	if v := q.Get("event_type"); v != "" {
		t := domain.EventType(v)
		if !t.Valid() {
			writeError(w, http.StatusBadRequest, "event_type "+v+" is not a canonical event type")
			return
		}
		query.EventType = t
	}
	if v := q.Get("mapping_complete"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "mapping_complete must be true or false")
			return
		}
		query.MappingComplete = &b
	}
	if t, ok := parseTime(q.Get("from")); ok {
		query.From = t
	}
	if t, ok := parseTime(q.Get("to")); ok {
		query.To = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		query.Limit = n
	}

	events, err := s.store.QueryEvents(r.Context(), id.TenantID, query)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	out := make([]dispatch.Payload, 0, len(events))
	for _, e := range events {
		// Rendered in the same shape the destination receives, so what an
		// engineer reads in the explorer is exactly what their handler was
		// sent — no translation, no "but the delivered version looked
		// different".
		out = append(out, dispatch.BuildPayload(e, nil))
	}

	resp := map[string]any{"events": out}
	if len(events) > 0 {
		resp["next_cursor"] = events[len(events)-1].ID
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleGetEvent returns one event with every delivery attempt (§3.2 D1).
func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	ev, err := s.store.GetCanonicalEvent(r.Context(), id.TenantID, r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	deliveries, err := s.store.ListDeliveriesForEvent(r.Context(), id.TenantID, ev.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	type attempt struct {
		ID            int64      `json:"id"`
		DestinationID string     `json:"destination_id"`
		Attempt       int        `json:"attempt"`
		Status        string     `json:"status"`
		ResponseCode  int        `json:"response_code,omitempty"`
		ResponseBody  string     `json:"response_body,omitempty"`
		Error         string     `json:"error,omitempty"`
		DurationMS    int        `json:"duration_ms,omitempty"`
		IsReplay      bool       `json:"is_replay"`
		NextRetryAt   *time.Time `json:"next_retry_at,omitempty"`
		CreatedAt     time.Time  `json:"created_at"`
	}
	attempts := make([]attempt, 0, len(deliveries))
	for _, d := range deliveries {
		a := attempt{
			ID: d.ID, DestinationID: d.DestinationID, Attempt: d.Attempt,
			Status: string(d.Status), ResponseCode: d.ResponseCode,
			ResponseBody: d.ResponseBody, Error: d.Error, DurationMS: d.DurationMS,
			IsReplay: d.IsReplay, CreatedAt: d.CreatedAt,
		}
		if !d.NextRetryAt.IsZero() {
			t := d.NextRetryAt
			a.NextRetryAt = &t
		}
		attempts = append(attempts, a)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"event":        dispatch.BuildPayload(ev, nil),
		"raw_event_id": ev.RawEventID,
		"deliveries":   attempts,
		// Named rather than implied: an engineer looking at an event that was
		// never delivered needs to know whether that is a bug or a
		// configuration.
		"delivery_count": len(attempts),
	})
}

// handleGetRawPayload returns the provider's original bytes.
//
// Separately permissioned and separately audited (§8.4). Raw bodies are the
// most sensitive thing StatusHub holds — they are whatever the provider chose
// to send, which is not something we control — so reading one is an event in
// its own right.
func (s *Server) handleGetRawPayload(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	ev, err := s.store.GetCanonicalEvent(r.Context(), id.TenantID, r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	raw, err := s.store.GetRawEvent(r.Context(), id.TenantID, ev.RawEventID)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	s.audit(r.Context(), id, domain.AuditRawPayloadRead,
		domain.Subject{Type: "raw_event", ID: raw.ID},
		map[string]any{"event": ev.ID, "provider": raw.Provider})

	writeJSON(w, http.StatusOK, map[string]any{
		"raw_event_id":    raw.ID,
		"provider":        raw.Provider,
		"received_at":     raw.ReceivedAt,
		"signature_valid": raw.SignatureValid,
		"body_sha256":     raw.BodySHA256,
		"headers":         raw.Headers,
		"body":            string(raw.Body),
		"redacted":        raw.Redacted,
		"redaction_note":  raw.RedactionNote,
	})
}

func (s *Server) handleReplayEvent(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.dispatcher == nil {
		writeError(w, http.StatusServiceUnavailable, "this instance does not run the dispatcher")
		return
	}

	var req struct {
		DestinationIDs []string `json:"destination_ids,omitempty"`
	}
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "request body: "+err.Error())
			return
		}
	}

	res, err := s.dispatcher.Replay(r.Context(), id.TenantID, dispatch.ReplayRequest{
		EventIDs: []string{r.PathValue("id")}, DestinationIDs: req.DestinationIDs,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, res)
}

// handleBulkReplay is the recovery tool (§3.2 C3).
func (s *Server) handleBulkReplay(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.dispatcher == nil {
		writeError(w, http.StatusServiceUnavailable, "this instance does not run the dispatcher")
		return
	}

	var req struct {
		EventIDs       []string `json:"event_ids,omitempty"`
		Provider       string   `json:"provider,omitempty"`
		Status         string   `json:"status,omitempty"`
		TransactionRef string   `json:"transaction_ref,omitempty"`
		From           string   `json:"from,omitempty"`
		To             string   `json:"to,omitempty"`
		DestinationIDs []string `json:"destination_ids,omitempty"`
		DryRun         bool     `json:"dry_run,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "request body: "+err.Error())
		return
	}

	rr := dispatch.ReplayRequest{
		EventIDs: req.EventIDs, DestinationIDs: req.DestinationIDs, DryRun: req.DryRun,
	}
	if len(req.EventIDs) == 0 {
		q := &store.EventQuery{
			Provider: req.Provider, TransactionRef: req.TransactionRef,
		}
		if req.Status != "" {
			st, err := domain.ParseStatus(req.Status)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			q.Status = st
		}
		if t, ok := parseTime(req.From); ok {
			q.From = t
		}
		if t, ok := parseTime(req.To); ok {
			q.To = t
		}
		rr.Filter = q
	}

	res, err := s.dispatcher.Replay(r.Context(), id.TenantID, rr)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !req.DryRun {
		s.audit(r.Context(), id, domain.AuditEventReplayed,
			domain.Subject{Type: "tenant", ID: id.TenantID},
			map[string]any{"matched": res.Matched, "queued": res.Queued, "destinations": res.Destinations})
	}
	writeJSON(w, http.StatusAccepted, res)
}

func (s *Server) handleQueryDeliveries(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	q := store.DeliveryQuery{
		DestinationID: strings.TrimSpace(r.URL.Query().Get("destination_id")),
		EventID:       strings.TrimSpace(r.URL.Query().Get("event_id")),
	}
	if v := r.URL.Query().Get("status"); v != "" {
		q.Status = domain.DeliveryStatus(v)
	}
	if v := r.URL.Query().Get("cursor"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "cursor must be an integer")
			return
		}
		q.Cursor = n
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, _ := strconv.Atoi(v)
		q.Limit = n
	}

	deliveries, err := s.store.QueryDeliveries(r.Context(), id.TenantID, q)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": deliveries})
}

func (s *Server) handleRetryDelivery(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.dispatcher == nil {
		writeError(w, http.StatusServiceUnavailable, "this instance does not run the dispatcher")
		return
	}
	deliveryID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "delivery id must be an integer")
		return
	}

	newID, err := s.dispatcher.RetryDeadLetter(r.Context(), id.TenantID, deliveryID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"queued_delivery_id": newID,
		// Stated explicitly, because "retry" reads like it might overwrite
		// the failure record, and it must not: the dead letter is evidence.
		"note": "the original dead letter is preserved; this is a new delivery",
	})
}

// handleUnknownStatuses is the to-do list the product generates for itself
// (§6.4, §11.2).
func (s *Server) handleUnknownStatuses(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	since := s.now().Add(-30 * 24 * time.Hour)
	if t, ok := parseTime(r.URL.Query().Get("since")); ok {
		since = t
	}
	unknown, err := s.store.UnknownStatuses(r.Context(), id.TenantID, since)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"since":            since,
		"unknown_statuses": unknown,
		"note": "each of these is a provider status value with no mapping. Events carrying them were " +
			"forwarded with status \"unknown\" rather than guessed at.",
	})
}
