package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/auth"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/metrics"
)

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	since := s.now().Add(-7 * 24 * time.Hour)
	if t, ok := parseTime(r.URL.Query().Get("since")); ok {
		since = t
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	records, err := s.store.ListAudit(r.Context(), id.TenantID, since, limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"since": since, "records": records})
}

// handleVerifyAudit walks the tenant's hash chain and publishes the proof
// (§8.3).
//
// It is exposed to the customer rather than kept internal on purpose. An
// audit trail whose integrity only the vendor can check is a trail the
// customer has to take on trust, which is precisely what an audit trail
// exists to avoid.
func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	proof, err := s.store.VerifyChain(r.Context(), id.TenantID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusOK
	if !proof.Intact {
		// A broken chain is not a 200 with a flag buried in the body. It is a
		// failure, and anything polling this endpoint should see it as one
		// without having to parse the response.
		status = http.StatusConflict
		s.log.ErrorContext(r.Context(), "audit chain verification failed",
			"tenant", id.TenantID, "broken_at", proof.BrokenAt, "reason", proof.Reason)
	}
	s.metrics.Set("statushub_audit_chain_intact",
		metrics.Labels{"tenant": id.TenantID}, boolGauge(proof.Intact))
	writeJSON(w, status, proof)
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

type createKeyRequest struct {
	Name        string `json:"name"`
	Role        string `json:"role"`
	Environment string `json:"environment"`
	TTLDays     int    `json:"ttl_days,omitempty"`
}

// handleCreateKey issues an API key.
//
// The plaintext appears in this response and nowhere else, ever. It is not
// stored, not logged, and not retrievable — which is stated in the response
// body too, because a customer who does not read that line will discover it
// the hard way.
func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}

	var req createKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "request body: "+err.Error())
		return
	}

	role := auth.Role(req.Role)
	if !role.Valid() {
		writeError(w, http.StatusBadRequest, "role must be owner, engineer, support or read_only")
		return
	}
	env, ok := parseEnvironment(req.Environment)
	if !ok {
		writeError(w, http.StatusBadRequest, "environment must be test or live")
		return
	}
	// A test key cannot mint a live one. Without this, environment scoping is
	// decoration: anyone with a test key could escalate to live in one call.
	if id.Environment != env {
		writeError(w, http.StatusForbidden,
			"this key is scoped to the "+id.Environment.String()+" environment and cannot issue "+env.String()+" keys")
		return
	}

	var ttl time.Duration
	if req.TTLDays > 0 {
		ttl = time.Duration(req.TTLDays) * 24 * time.Hour
	}

	plaintext, key, err := auth.Issue(id.TenantID, env, role, req.Name, ttl)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.keys.PutKey(r.Context(), key); err != nil {
		writeStoreError(w, err)
		return
	}

	s.audit(r.Context(), id, domain.AuditAPIKeyCreated,
		domain.Subject{Type: "api_key", ID: key.ID},
		map[string]any{
			"role": role.String(), "environment": env.String(),
			"name": req.Name, "prefix": key.Prefix,
			// The plaintext is not in the audit payload. An audit trail is
			// read by more people than a secret store.
		})

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          key.ID,
		"key":         plaintext,
		"prefix":      key.Prefix,
		"role":        role.String(),
		"environment": env.String(),
		"expires_at":  nullableTime(key.ExpiresAt),
		"warning":     "this is the only time the key is shown. It is stored as an Argon2id hash and cannot be recovered.",
	})
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	keys, err := s.keys.ListKeys(r.Context(), id.TenantID)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	type view struct {
		ID          string     `json:"id"`
		Name        string     `json:"name,omitempty"`
		Prefix      string     `json:"prefix"`
		Role        string     `json:"role"`
		Environment string     `json:"environment"`
		CreatedAt   time.Time  `json:"created_at"`
		LastUsed    *time.Time `json:"last_used,omitempty"`
		ExpiresAt   *time.Time `json:"expires_at,omitempty"`
		RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	}
	out := make([]view, 0, len(keys))
	for _, k := range keys {
		out = append(out, view{
			ID: k.ID, Name: k.Name, Prefix: k.Prefix, Role: k.Role.String(),
			Environment: k.Environment.String(), CreatedAt: k.CreatedAt,
			LastUsed: nullableTime(k.LastUsed), ExpiresAt: nullableTime(k.ExpiresAt),
			RevokedAt: nullableTime(k.RevokedAt),
		})
	}
	// LastUsed is here because the most useful thing an owner can do with
	// this list is revoke the keys nobody has used in six months.
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	keyID := r.PathValue("id")

	// Revoking the key you are currently using would lock the tenant out of
	// their own account with no way back in. Refusing is kinder than being
	// technically correct.
	if keyID == id.KeyID {
		writeError(w, http.StatusBadRequest,
			"this is the key you are authenticated with; issue a replacement first, then revoke this one")
		return
	}

	if err := s.keys.RevokeKey(r.Context(), id.TenantID, keyID, s.now()); err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	s.audit(r.Context(), id, domain.AuditAPIKeyRevoked,
		domain.Subject{Type: "api_key", ID: keyID}, nil)
	w.WriteHeader(http.StatusNoContent)
}

func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
