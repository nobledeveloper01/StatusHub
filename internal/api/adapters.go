package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"sync"

	"github.com/nobledeveloper01/StatusHub/internal/adapters/declarative"
	"github.com/nobledeveloper01/StatusHub/internal/auth"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// AdapterStore persists uploaded declarative adapters.
type AdapterStore interface {
	PutAdapter(ctx context.Context, tenantID string, cfg declarative.Config, raw []byte) error
	GetAdapter(ctx context.Context, tenantID, name string) (declarative.Config, error)
	ListAdapters(ctx context.Context, tenantID string) ([]declarative.Config, error)
	DeleteAdapter(ctx context.Context, tenantID, name string) error
}

// ErrAdapterNotFound is returned for an adapter a tenant does not have.
var ErrAdapterNotFound = errors.New("no such adapter")

// MemoryAdapterStore is the in-memory implementation.
type MemoryAdapterStore struct {
	mu       sync.RWMutex
	byTenant map[string]map[string]declarative.Config
}

// NewMemoryAdapterStore returns an empty adapter store.
func NewMemoryAdapterStore() *MemoryAdapterStore {
	return &MemoryAdapterStore{byTenant: map[string]map[string]declarative.Config{}}
}

func (s *MemoryAdapterStore) PutAdapter(_ context.Context, tenantID string, cfg declarative.Config, _ []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byTenant[tenantID] == nil {
		s.byTenant[tenantID] = map[string]declarative.Config{}
	}
	s.byTenant[tenantID][cfg.Name] = cfg
	return nil
}

func (s *MemoryAdapterStore) GetAdapter(_ context.Context, tenantID, name string) (declarative.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.byTenant[tenantID][name]
	if !ok {
		return declarative.Config{}, ErrAdapterNotFound
	}
	return cfg, nil
}

func (s *MemoryAdapterStore) ListAdapters(_ context.Context, tenantID string) ([]declarative.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]declarative.Config, 0, len(s.byTenant[tenantID]))
	for _, cfg := range s.byTenant[tenantID] {
		out = append(out, cfg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *MemoryAdapterStore) DeleteAdapter(_ context.Context, tenantID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byTenant[tenantID][name]; !ok {
		return ErrAdapterNotFound
	}
	delete(s.byTenant[tenantID], name)
	return nil
}

// handleListAdapters returns the built-in adapters and the tenant's own,
// each documented the same way.
func (s *Server) handleListAdapters(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}

	type entry struct {
		BuiltIn     bool `json:"built_in"`
		Description any  `json:"description"`
	}
	out := make([]entry, 0, 8)
	for _, d := range s.registry.Describe() {
		out = append(out, entry{BuiltIn: true, Description: d})
	}

	own, err := s.adapterStore.ListAdapters(r.Context(), id.TenantID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for _, cfg := range own {
		a, cerr := declarative.Compile(cfg)
		if cerr != nil {
			// A stored adapter that no longer compiles is worth showing, with
			// the reason. Hiding it would leave an endpoint referring to
			// something that does not appear anywhere in the dashboard.
			out = append(out, entry{Description: map[string]string{
				"name": cfg.Name, "error": cerr.Error(),
			}})
			continue
		}
		out = append(out, entry{Description: a.Describe()})
	}
	writeJSON(w, http.StatusOK, map[string]any{"adapters": out})
}

type uploadAdapterRequest struct {
	Config json.RawMessage `json:"config"`

	// Samples, when supplied, are run before the adapter is stored. Uploading
	// with samples is the recommended path and the dashboard always does it:
	// an adapter that has never seen a real payload is an adapter nobody
	// knows the behaviour of.
	Samples []declarative.Sample `json:"samples,omitempty"`
}

// handleUploadAdapter validates, tests and registers a declarative adapter.
func (s *Server) handleUploadAdapter(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}

	var req uploadAdapterRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "request body: "+err.Error())
		return
	}

	cfg, err := declarative.Parse(req.Config)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := cfg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.registry.IsBuiltIn(cfg.Name) {
		writeError(w, http.StatusConflict,
			cfg.Name+" is a built-in adapter and cannot be redefined; choose another name")
		return
	}

	result := declarative.Test(cfg, declarative.TestRequest{Payloads: req.Samples})
	if !result.Valid {
		writeError(w, http.StatusBadRequest, result.Error)
		return
	}
	// A sample that does not parse blocks the upload. The customer supplied
	// it as an example of what the provider sends, so an adapter that cannot
	// read it is not ready, whatever else it does.
	for _, sr := range result.Samples {
		if !sr.Parsed {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "a supplied sample did not parse", "test": result,
			})
			return
		}
	}

	compiled, err := declarative.Compile(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.adapterStore.PutAdapter(r.Context(), id.TenantID, cfg, req.Config); err != nil {
		writeStoreError(w, err)
		return
	}
	if err := s.registry.Register(id.TenantID, compiled); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	// Recorded against the engineer who made the change (§6.4). An adapter
	// edit silently alters what every future event from that provider means,
	// so who made it is the first question after anything goes wrong.
	s.audit(r.Context(), id, domain.AuditAdapterUploaded,
		domain.Subject{Type: "adapter", ID: cfg.Name},
		map[string]any{
			"version":       cfg.Version,
			"verification":  cfg.Verification.Type,
			"status_values": len(cfg.Mapping.Status.Values),
			"samples_run":   len(req.Samples),
		})

	writeJSON(w, http.StatusCreated, map[string]any{
		"adapter": compiled.Describe(),
		"test":    result,
	})
}

// handleTestAdapter is the dry run (§7.3). It stores nothing and registers
// nothing, so a broken adapter cannot reach live traffic by being tested.
func (s *Server) handleTestAdapter(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	name := r.PathValue("name")

	var req struct {
		Config   json.RawMessage      `json:"config,omitempty"`
		Payloads []declarative.Sample `json:"payloads"`
		Secret   string               `json:"secret,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "request body: "+err.Error())
		return
	}

	// Either test a configuration supplied inline — which is what the editor
	// does on every keystroke — or the stored one.
	var cfg declarative.Config
	if len(req.Config) > 0 {
		cfg, err = declarative.Parse(req.Config)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		cfg, err = s.adapterStore.GetAdapter(r.Context(), id.TenantID, name)
		if err != nil {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
	}

	writeJSON(w, http.StatusOK, declarative.Test(cfg, declarative.TestRequest{
		Payloads: req.Payloads, Secret: req.Secret,
	}))
}

// handleDeleteAdapter removes a tenant's adapter.
func (s *Server) handleDeleteAdapter(w http.ResponseWriter, r *http.Request) {
	id, err := auth.FromContext(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	name := r.PathValue("name")

	// An adapter still referenced by an endpoint must not be deletable. The
	// endpoint would keep receiving webhooks it can no longer verify, and
	// every one of them would be stored flagged invalid and never forwarded —
	// which looks exactly like an attack in the dashboard.
	endpoints, err := s.store.ListEndpoints(r.Context(), id.TenantID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for _, ep := range endpoints {
		if ep.AdapterName == name {
			writeError(w, http.StatusConflict,
				"endpoint "+ep.ID+" still uses this adapter; delete or repoint it first")
			return
		}
	}

	if err := s.adapterStore.DeleteAdapter(r.Context(), id.TenantID, name); err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	s.registry.Unregister(id.TenantID, name)
	s.audit(r.Context(), id, domain.AuditAdapterDeleted,
		domain.Subject{Type: "adapter", ID: name}, nil)
	w.WriteHeader(http.StatusNoContent)
}

// LoadTenantAdapters registers every stored adapter at start-up. Without it a
// restart leaves endpoints pointing at adapters the registry has never heard
// of, and every webhook to them fails verification.
func LoadTenantAdapters(ctx context.Context, s *Server) error {
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return err
	}
	for _, t := range tenants {
		configs, err := s.adapterStore.ListAdapters(ctx, t.ID)
		if err != nil {
			return err
		}
		for _, cfg := range configs {
			a, err := declarative.Compile(cfg)
			if err != nil {
				// Logged and skipped rather than fatal: one tenant's broken
				// adapter must not stop the process starting for everyone
				// else.
				s.log.ErrorContext(ctx, "stored adapter no longer compiles and was not loaded",
					"tenant", t.ID, "adapter", cfg.Name, "error", err)
				continue
			}
			if err := s.registry.Register(t.ID, a); err != nil {
				s.log.ErrorContext(ctx, "could not register a stored adapter",
					"tenant", t.ID, "adapter", cfg.Name, "error", err)
			}
		}
	}
	return nil
}
