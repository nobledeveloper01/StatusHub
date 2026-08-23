package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Idempotency, per §8.6 point 4: every write endpoint accepts an idempotency
// key and returns the original result on replay.
//
// Without it, a retried "create endpoint" during a network blip issues a
// second receiver token, and the operator has two URLs with no way to tell
// which one the provider is actually calling. That is a genuinely bad
// afternoon, and it is entirely avoidable.

// IdempotencyHeader is the header callers send.
const IdempotencyHeader = "Idempotency-Key"

// IdempotencyWindow is how long a key is remembered.
//
// Twenty-four hours. Long enough to cover any client's retry schedule —
// including a human re-running a script the next morning — and short enough
// that the store does not become a permanent log of every write ever made.
const IdempotencyWindow = 24 * time.Hour

// maxRecordedBody bounds what is kept per key. A response larger than this is
// executed and returned, but not replayable; the alternative is an
// idempotency store that grows with response size rather than request count.
const maxRecordedBody = 64 << 10

var (
	// ErrIdempotencyConflict means the key was reused with a different
	// request body.
	//
	// This is the case worth being strict about. Returning the first
	// response would answer a question the caller did not ask; executing the
	// second silently makes the key meaningless. A 409 tells them their
	// client has a bug, which it does.
	ErrIdempotencyConflict = errors.New("this idempotency key was used with a different request")

	// ErrIdempotencyInFlight means the original request has not finished.
	ErrIdempotencyInFlight = errors.New("a request with this idempotency key is still in progress")
)

// IdempotencyRecord is a completed write.
type IdempotencyRecord struct {
	Key         string
	TenantID    string
	Method      string
	Path        string
	RequestHash string

	Status   int
	Body     []byte
	Replayed bool

	InFlight  bool
	CreatedAt time.Time
}

// IdempotencyStore holds records.
type IdempotencyStore interface {
	// Begin claims a key. It returns the existing record when one is present,
	// which is what makes this a claim rather than a check followed by a
	// write — two concurrent retries must not both execute.
	Begin(ctx context.Context, r IdempotencyRecord) (existing *IdempotencyRecord, err error)

	Complete(ctx context.Context, key, tenantID string, status int, body []byte) error

	// Abandon releases a key whose request failed before completing, so a
	// caller can retry rather than being told their own retry is still in
	// flight for the next 24 hours.
	Abandon(ctx context.Context, key, tenantID string) error
}

// MemoryIdempotencyStore is the in-memory implementation.
type MemoryIdempotencyStore struct {
	mu      sync.Mutex
	records map[string]*IdempotencyRecord
	now     func() time.Time
}

// NewMemoryIdempotencyStore returns an empty store.
func NewMemoryIdempotencyStore() *MemoryIdempotencyStore {
	return &MemoryIdempotencyStore{
		records: map[string]*IdempotencyRecord{},
		now:     func() time.Time { return time.Now().UTC() },
	}
}

func idempotencyKey(tenantID, key string) string { return tenantID + "|" + key }

func (s *MemoryIdempotencyStore) Begin(_ context.Context, r IdempotencyRecord) (*IdempotencyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := idempotencyKey(r.TenantID, r.Key)
	if existing, ok := s.records[k]; ok {
		if s.now().Sub(existing.CreatedAt) < IdempotencyWindow {
			out := *existing
			return &out, nil
		}
		// Past the window the key is forgotten, so a script re-run a week
		// later executes rather than replaying a stale response.
		delete(s.records, k)
	}

	r.InFlight = true
	r.CreatedAt = s.now()
	s.records[k] = &r
	return nil, nil
}

func (s *MemoryIdempotencyStore) Complete(_ context.Context, key, tenantID string, status int, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[idempotencyKey(tenantID, key)]
	if !ok {
		return errors.New("no such idempotency key")
	}
	rec.InFlight = false
	rec.Status = status
	if len(body) <= maxRecordedBody {
		rec.Body = append([]byte(nil), body...)
	}
	return nil
}

func (s *MemoryIdempotencyStore) Abandon(_ context.Context, key, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, idempotencyKey(tenantID, key))
	return nil
}

// Sweep forgets records past the window.
func (s *MemoryIdempotencyStore) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := s.now().Add(-IdempotencyWindow)
	var removed int
	for k, r := range s.records {
		if r.CreatedAt.Before(cutoff) {
			delete(s.records, k)
			removed++
		}
	}
	return removed
}

// idempotent wraps a write handler.
//
// A request with no key is executed normally. Idempotency is opt-in per
// request rather than mandatory, because forcing every caller to generate a
// key would break every curl command in the documentation for a guarantee
// most of them do not need.
func (s *Server) idempotent(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get(IdempotencyHeader)
		if key == "" || s.idempotency == nil {
			next(w, r)
			return
		}
		if len(key) > 255 {
			writeError(w, http.StatusBadRequest, "idempotency key must be at most 255 characters")
			return
		}

		tenantID := ""
		if id, err := identityFrom(r); err == nil {
			tenantID = id
		}
		if tenantID == "" {
			writeError(w, http.StatusUnauthorized, "unauthorised")
			return
		}

		// The body has to be read here to hash it, and read again by the
		// handler, so it is buffered. Bounded by the same ceiling the handler
		// would apply.
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, "could not read the request body")
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))

		// Hashed over the canonical form, so a client whose JSON serialiser
		// reorders map keys between retries is not told its own retry is a
		// different request.
		sum := sha256.Sum256(append([]byte(r.Method+" "+r.URL.Path+"\n"), canonicalRequestBody(body)...))
		hash := hex.EncodeToString(sum[:])

		existing, err := s.idempotency.Begin(r.Context(), IdempotencyRecord{
			Key: key, TenantID: tenantID, Method: r.Method, Path: r.URL.Path, RequestHash: hash,
		})
		if err != nil {
			writeStoreError(w, err)
			return
		}

		if existing != nil {
			switch {
			case existing.RequestHash != hash:
				// Strict on purpose. Returning the first response would
				// answer a question this caller did not ask; executing this
				// one makes the key meaningless.
				writeError(w, http.StatusConflict, ErrIdempotencyConflict.Error())
			case existing.InFlight:
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusConflict, ErrIdempotencyInFlight.Error())
			default:
				// The original result, byte for byte, with a header saying so
				// — a caller that cannot tell a replay from a fresh execution
				// cannot tell whether their retry did anything.
				w.Header().Set("Idempotency-Replayed", "true")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(existing.Status)
				_, _ = w.Write(existing.Body)
			}
			return
		}

		rec := &recordingWriter{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)

		// Only successes are recorded. Replaying a 500 would tell a caller
		// their retry failed when it might now succeed, and replaying a 400
		// would keep answering a request they have since corrected.
		if rec.status >= 200 && rec.status < 300 {
			if err := s.idempotency.Complete(r.Context(), key, tenantID, rec.status, rec.body.Bytes()); err != nil {
				s.log.ErrorContext(r.Context(), "could not record an idempotent result",
					"key", key, "tenant", tenantID, "error", err)
			}
			return
		}
		if err := s.idempotency.Abandon(r.Context(), key, tenantID); err != nil {
			s.log.ErrorContext(r.Context(), "could not release an idempotency key after a failure",
				"key", key, "tenant", tenantID, "error", err)
		}
	}
}

// recordingWriter captures a handler's response so it can be replayed.
type recordingWriter struct {
	http.ResponseWriter
	status  int
	body    bytes.Buffer
	written bool
}

func (w *recordingWriter) WriteHeader(status int) {
	if w.written {
		return
	}
	w.written = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	if w.body.Len()+len(b) <= maxRecordedBody {
		w.body.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

// canonicalRequestBody normalises a JSON body before hashing, so a client
// whose serialiser reorders map keys between retries is not told its own
// retry is a different request.
func canonicalRequestBody(body []byte) []byte {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return body
	}
	out, err := json.Marshal(sortedAny(v))
	if err != nil {
		return body
	}
	return out
}

func sortedAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(t))
		for _, k := range keys {
			out[k] = sortedAny(t[k])
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = sortedAny(e)
		}
		return out
	default:
		return v
	}
}
