// Package secret resolves the signing secrets the database only ever holds a
// reference to (§10.2).
//
// The rule the whole package exists to enforce: a database dump is not a
// credential breach. Every row that needs a secret stores a reference such as
// `env://PAYSTACK_LIVE` or `kms://arn:aws:kms:...`, and the usable value is
// fetched at the moment it is needed and never written back.
package secret

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ErrNoSuchSecret = errors.New("secret reference does not resolve")
	ErrBadReference = errors.New("secret reference is malformed")
)

// Resolver turns a reference into a usable secret.
type Resolver interface {
	// Resolve returns the current secret for a reference.
	Resolve(ctx context.Context, ref string) (string, error)

	// ResolveAll returns every currently-valid secret for a reference,
	// newest first.
	//
	// Rotation is the reason this exists. A secret swapped atomically
	// rejects every in-flight event signed with the old one, which turns a
	// routine rotation into lost webhooks. Returning both lets verification
	// try each in turn, so the old and new secrets are valid together for as
	// long as the overlap window lasts and rotation never drops an event
	// (§8.2).
	ResolveAll(ctx context.Context, ref string) ([]string, error)
}

// Env resolves `env://NAME` references from the process environment, which is
// how secrets arrive in a container from a cloud secret manager. Rotation
// overlap is expressed as `env://NAME` plus an optional `NAME_PREVIOUS`.
type Env struct{}

// NewEnv returns the environment resolver.
func NewEnv() *Env { return &Env{} }

func (e *Env) Resolve(ctx context.Context, ref string) (string, error) {
	all, err := e.ResolveAll(ctx, ref)
	if err != nil {
		return "", err
	}
	return all[0], nil
}

func (e *Env) ResolveAll(_ context.Context, ref string) ([]string, error) {
	name, ok := strings.CutPrefix(ref, "env://")
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an env:// reference", ErrBadReference, ref)
	}
	if name == "" || strings.ContainsAny(name, " \t\r\n") {
		return nil, fmt.Errorf("%w: %q", ErrBadReference, ref)
	}
	v, present := os.LookupEnv(name)
	if !present || v == "" {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchSecret, ref)
	}
	out := []string{v}
	if prev := os.Getenv(name + "_PREVIOUS"); prev != "" && prev != v {
		out = append(out, prev)
	}
	return out, nil
}

// Static resolves from an in-process map. For tests and for `--store memory`
// evaluation, never for a live deployment — which the server enforces rather
// than documents.
type Static struct {
	mu      sync.RWMutex
	secrets map[string][]string
}

// NewStatic returns an empty static resolver.
func NewStatic() *Static { return &Static{secrets: map[string][]string{}} }

// Set replaces the secrets for a reference, newest first.
func (s *Static) Set(ref string, values ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[ref] = values
}

func (s *Static) Resolve(ctx context.Context, ref string) (string, error) {
	all, err := s.ResolveAll(ctx, ref)
	if err != nil {
		return "", err
	}
	return all[0], nil
}

func (s *Static) ResolveAll(_ context.Context, ref string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.secrets[ref]
	if !ok || len(v) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchSecret, ref)
	}
	return append([]string(nil), v...), nil
}

// Cached wraps a resolver with a short-lived cache.
//
// The TTL is short on purpose. The receiver resolves a secret on every
// request and a KMS round trip per webhook would blow the 50 ms p99 budget on
// its own — but a revoked secret that stays usable for an hour is a
// revocation that did not happen. Thirty seconds keeps the hot path fast
// while bounding how long a compromised secret outlives its revocation.
type Cached struct {
	inner Resolver
	ttl   time.Duration

	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	values  []string
	expires time.Time
}

// NewCached wraps inner. A non-positive ttl means thirty seconds.
func NewCached(inner Resolver, ttl time.Duration) *Cached {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Cached{inner: inner, ttl: ttl, entries: map[string]cacheEntry{}}
}

func (c *Cached) Resolve(ctx context.Context, ref string) (string, error) {
	all, err := c.ResolveAll(ctx, ref)
	if err != nil {
		return "", err
	}
	return all[0], nil
}

func (c *Cached) ResolveAll(ctx context.Context, ref string) ([]string, error) {
	now := time.Now()
	c.mu.RLock()
	e, ok := c.entries[ref]
	c.mu.RUnlock()
	if ok && e.expires.After(now) {
		return append([]string(nil), e.values...), nil
	}

	v, err := c.inner.ResolveAll(ctx, ref)
	if err != nil {
		// A stale entry is not served past its expiry even when the backend
		// is unreachable. Serving one would mean a KMS outage silently
		// extends every revocation, and the failure mode we want is
		// "verification is unavailable", which is loud, not "verification
		// uses a secret we were told to stop trusting", which is silent.
		return nil, err
	}
	c.mu.Lock()
	c.entries[ref] = cacheEntry{values: v, expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return append([]string(nil), v...), nil
}

// Invalidate drops a cached reference, so an explicit rotation takes effect
// immediately rather than at the end of the TTL.
func (c *Cached) Invalidate(ref string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, ref)
}

// Multi tries several resolvers in order, so one deployment can mix
// `env://` and a cloud provider's references during a migration.
type Multi struct {
	byScheme map[string]Resolver
}

// NewMulti builds a resolver that dispatches on the reference's scheme.
func NewMulti(byScheme map[string]Resolver) *Multi { return &Multi{byScheme: byScheme} }

func (m *Multi) Resolve(ctx context.Context, ref string) (string, error) {
	r, err := m.pick(ref)
	if err != nil {
		return "", err
	}
	return r.Resolve(ctx, ref)
}

func (m *Multi) ResolveAll(ctx context.Context, ref string) ([]string, error) {
	r, err := m.pick(ref)
	if err != nil {
		return nil, err
	}
	return r.ResolveAll(ctx, ref)
}

func (m *Multi) pick(ref string) (Resolver, error) {
	scheme, _, ok := strings.Cut(ref, "://")
	if !ok {
		return nil, fmt.Errorf("%w: %q has no scheme", ErrBadReference, ref)
	}
	r, ok := m.byScheme[scheme]
	if !ok {
		return nil, fmt.Errorf("%w: no resolver for scheme %q", ErrBadReference, scheme)
	}
	return r, nil
}
