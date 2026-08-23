package auth

import (
	"context"
	"errors"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// Identity is who is making a request. Every handler that touches
// tenant-owned data takes its tenant ID from here and never from the URL,
// the body or a query parameter — a tenant ID the caller supplies is not an
// identity, it is a suggestion.
type Identity struct {
	TenantID    string
	TenantSlug  string
	KeyID       string
	Role        Role
	Environment domain.Environment
	IP          string
}

// Actor renders the identity for the audit trail.
func (i Identity) Actor() domain.Actor {
	return domain.Actor{Type: domain.ActorAPIKey, ID: i.KeyID, IP: i.IP}
}

// Can reports whether the identity holds at least the given role.
func (i Identity) Can(need Role) bool { return i.Role.AtLeast(need) }

type contextKey struct{}

// ErrNoIdentity means a handler asked for the caller and there was none. It
// is a programming error rather than an authentication failure: a route that
// reaches a handler without passing through the middleware is a route that
// forgot to be protected, and it must fail loudly rather than default to
// anything.
var ErrNoIdentity = errors.New("request has no authenticated identity")

// WithIdentity attaches the caller to a context.
func WithIdentity(ctx context.Context, i Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, i)
}

// FromContext returns the caller.
func FromContext(ctx context.Context) (Identity, error) {
	i, ok := ctx.Value(contextKey{}).(Identity)
	if !ok || i.TenantID == "" {
		return Identity{}, ErrNoIdentity
	}
	return i, nil
}

// MustTenant returns the caller's tenant, or an error. Handlers call this
// rather than reading a tenant from anywhere else, which is what makes
// cross-tenant access a thing that cannot be expressed rather than a thing
// that is checked.
func MustTenant(ctx context.Context) (string, error) {
	i, err := FromContext(ctx)
	if err != nil {
		return "", err
	}
	return i.TenantID, nil
}
