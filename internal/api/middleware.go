// Package api is the management surface from §7.3.
//
// Every route here is authenticated, every handler takes its tenant from the
// authenticated identity rather than from the request, and every write is
// audited. There is deliberately no route that accepts a tenant ID as a
// parameter: an identifier the caller supplies is a suggestion, not an
// identity.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/auth"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

// authenticate resolves the bearer key and attaches the identity.
//
// Every failure returns the same 401 with the same body. The reasons are
// distinguished in the log and the metric, never in the response: telling a
// caller that a key exists but is revoked, or is for the wrong environment,
// is telling them which of their stolen keys are real.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix, secret, env, err := auth.Parse(r.Header.Get("Authorization"))
		if err != nil {
			s.unauthorised(r, "malformed", err)
			writeError(w, http.StatusUnauthorized, "unauthorised")
			return
		}

		key, err := s.keys.GetKeyByPrefix(r.Context(), prefix)
		if err != nil {
			s.unauthorised(r, "unknown", err)
			writeError(w, http.StatusUnauthorized, "unauthorised")
			return
		}
		if err := auth.Check(&key, secret, s.now(), env); err != nil {
			s.unauthorised(r, reasonFor(err), err)
			writeError(w, http.StatusUnauthorized, "unauthorised")
			return
		}

		tenant, err := s.store.GetTenant(r.Context(), key.TenantID)
		if err != nil {
			s.unauthorised(r, "tenant_missing", err)
			writeError(w, http.StatusUnauthorized, "unauthorised")
			return
		}

		id := auth.Identity{
			TenantID:    key.TenantID,
			TenantSlug:  tenant.Slug,
			KeyID:       key.ID,
			Role:        key.Role,
			Environment: key.Environment,
			IP:          clientIP(r),
		}
		// Best effort, and deliberately not awaited on the response path.
		go func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
			defer cancel()
			_ = s.keys.TouchKey(ctx, key.ID, s.now())
		}()

		next.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), id)))
	})
}

func reasonFor(err error) string {
	switch {
	case errors.Is(err, auth.ErrRevoked):
		return "revoked"
	case errors.Is(err, auth.ErrExpired):
		return "expired"
	case errors.Is(err, auth.ErrWrongEnv):
		return "wrong_environment"
	default:
		return "bad_secret"
	}
}

func (s *Server) unauthorised(r *http.Request, reason string, err error) {
	s.log.WarnContext(r.Context(), "management API request rejected",
		"reason", reason, "path", r.URL.Path, "method", r.Method,
		"source_ip", clientIP(r), "error", err)
}

// requireRole wraps a handler with a minimum role.
//
// A caller who is authenticated but lacks the role gets 403, not 404. That is
// the opposite of the cross-tenant rule, and deliberately so: here the caller
// already knows the resource is theirs, so hiding its existence achieves
// nothing and only makes a permissions problem look like a bug.
func requireRole(need auth.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorised")
			return
		}
		if !id.Can(need) {
			writeError(w, http.StatusForbidden,
				"this key has the "+id.Role.String()+" role; "+need.String()+" or higher is required")
			return
		}
		next(w, r)
	}
}

// recoverPanic turns a handler panic into a 500 rather than a dropped
// connection, and logs it with the route.
func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.log.ErrorContext(r.Context(), "handler panicked",
					"path", r.URL.Path, "method", r.Method, "panic", v)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeaders are set on every response. They cost nothing and remove a
// class of finding from every penetration test the customer will run.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// writeStoreError maps a store error onto a status.
//
// ErrNotFound becomes 404 whether the row is absent or belongs to another
// tenant. The two must be indistinguishable, or a caller with one valid key
// can enumerate another fintech's event IDs one request at a time (§8.1).
func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrDuplicate):
		writeError(w, http.StatusConflict, "already exists")
	case errors.Is(err, auth.ErrNoIdentity):
		writeError(w, http.StatusUnauthorized, "unauthorised")
	default:
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func decodeJSON(r *http.Request, v any) error {
	// Bounded, like everything else. A management API is authenticated, which
	// makes an oversized body a mistake rather than an attack — but an
	// unbounded read is still an unbounded read.
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func parseTime(s string) (time.Time, bool) {
	if strings.TrimSpace(s) == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func parseEnvironment(s string) (domain.Environment, bool) {
	e := domain.Environment(strings.TrimSpace(s))
	return e, e.Valid()
}
