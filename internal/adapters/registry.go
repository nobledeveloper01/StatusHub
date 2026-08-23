// Package adapters is the registry of provider integrations. It is the only
// package that knows the full list, so adding a provider is one import and
// one line here.
package adapters

import (
	"fmt"
	"sort"
	"sync"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/flutterwave"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/paystack"
)

// ErrUnknownAdapter is returned when an endpoint names an adapter that is
// neither built in nor registered as a declarative one.
var ErrUnknownAdapter = fmt.Errorf("unknown adapter")

// Registry resolves an adapter name to an implementation.
//
// Built-in adapters are registered once at construction. Declarative
// adapters are registered per tenant at runtime, and the two namespaces are
// kept apart: a tenant uploading an adapter called "paystack" gets their own
// version for their own endpoints and cannot shadow the built-in one for
// anybody else — including for themselves by accident, since a built-in name
// is refused at upload.
type Registry struct {
	mu       sync.RWMutex
	builtin  map[string]adapter.Adapter
	declared map[string]map[string]adapter.Adapter // tenantID -> name -> adapter
}

// New returns a registry with every built-in adapter loaded.
func New() *Registry {
	r := &Registry{
		builtin:  map[string]adapter.Adapter{},
		declared: map[string]map[string]adapter.Adapter{},
	}
	for _, a := range []adapter.Adapter{
		paystack.New(),
		flutterwave.New(),
	} {
		r.builtin[a.Name()] = a
	}
	return r
}

// IsBuiltIn reports whether a name belongs to a shipped adapter.
func (r *Registry) IsBuiltIn(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.builtin[name]
	return ok
}

// Get resolves an adapter for a tenant. A tenant's own declarative adapter
// wins over a built-in of the same name only if one somehow exists; upload
// validation prevents that, and the ordering here is defence in depth rather
// than a feature.
func (r *Registry) Get(tenantID, name string) (adapter.Adapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if byName, ok := r.declared[tenantID]; ok {
		if a, ok := byName[name]; ok {
			return a, nil
		}
	}
	if a, ok := r.builtin[name]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownAdapter, name)
}

// Register installs a tenant's declarative adapter.
func (r *Registry) Register(tenantID string, a adapter.Adapter) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.builtin[a.Name()]; ok {
		return fmt.Errorf("%q is a built-in adapter name and cannot be redefined", a.Name())
	}
	if r.declared[tenantID] == nil {
		r.declared[tenantID] = map[string]adapter.Adapter{}
	}
	r.declared[tenantID][a.Name()] = a
	return nil
}

// Unregister removes a tenant's declarative adapter.
func (r *Registry) Unregister(tenantID, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if byName, ok := r.declared[tenantID]; ok {
		delete(byName, name)
	}
}

// BuiltInNames lists the shipped adapters, sorted, for the dashboard and the
// CLI.
func (r *Registry) BuiltInNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.builtin))
	for n := range r.builtin {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Describe returns the self-documentation for every built-in adapter, which
// is what the adapter list in the dashboard renders. An adapter that does not
// implement Describable still appears, with only its name — visible and
// obviously undocumented beats absent.
func (r *Registry) Describe() []adapter.Description {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]adapter.Description, 0, len(r.builtin))
	for name, a := range r.builtin {
		if d, ok := a.(adapter.Describable); ok {
			out = append(out, d.Describe())
			continue
		}
		out = append(out, adapter.Description{Name: name, DisplayName: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
