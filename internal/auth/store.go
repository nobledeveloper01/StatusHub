package auth

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// KeyStore holds issued keys.
type KeyStore interface {
	PutKey(ctx context.Context, k Key) error

	// GetKeyByPrefix looks a key up by its plaintext prefix. It is not tenant
	// scoped, because the tenant is what it resolves — and it is the only
	// method in the system with that property.
	GetKeyByPrefix(ctx context.Context, prefix string) (Key, error)

	ListKeys(ctx context.Context, tenantID string) ([]Key, error)
	RevokeKey(ctx context.Context, tenantID, keyID string, at time.Time) error
	TouchKey(ctx context.Context, keyID string, at time.Time) error
}

// ErrKeyNotFound is returned for a prefix that resolves to nothing.
var ErrKeyNotFound = errors.New("no such key")

// MemoryKeyStore is the in-memory implementation.
type MemoryKeyStore struct {
	mu       sync.RWMutex
	byID     map[string]Key
	byPrefix map[string]string
}

// NewMemoryKeyStore returns an empty key store.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{byID: map[string]Key{}, byPrefix: map[string]string{}}
}

func (s *MemoryKeyStore) PutKey(_ context.Context, k Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, clash := s.byPrefix[k.Prefix]; clash {
		// Two keys sharing a prefix would make lookup ambiguous. With 120
		// bits of entropy after the prefix this is effectively impossible,
		// but "effectively impossible" is not a reason to resolve it wrongly
		// if it happens.
		return errors.New("a key with that prefix already exists")
	}
	s.byID[k.ID] = k
	s.byPrefix[k.Prefix] = k.ID
	return nil
}

func (s *MemoryKeyStore) GetKeyByPrefix(_ context.Context, prefix string) (Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byPrefix[prefix]
	if !ok {
		return Key{}, ErrKeyNotFound
	}
	return s.byID[id], nil
}

func (s *MemoryKeyStore) ListKeys(_ context.Context, tenantID string) ([]Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Key
	for _, k := range s.byID {
		if k.TenantID == tenantID {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryKeyStore) RevokeKey(_ context.Context, tenantID, keyID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byID[keyID]
	if !ok || k.TenantID != tenantID {
		return ErrKeyNotFound
	}
	k.RevokedAt = at
	s.byID[keyID] = k
	return nil
}

// TouchKey records last use. Best-effort: a failure here must never fail the
// request it is describing.
func (s *MemoryKeyStore) TouchKey(_ context.Context, keyID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byID[keyID]
	if !ok {
		return ErrKeyNotFound
	}
	k.LastUsed = at
	s.byID[keyID] = k
	return nil
}

// Bootstrap issues an owner key for a new tenant and stores it. It exists so
// that provisioning a tenant is one call rather than a sequence a caller can
// get half-way through.
func Bootstrap(ctx context.Context, ks KeyStore, tenantID string, env domain.Environment) (string, Key, error) {
	plaintext, key, err := Issue(tenantID, env, RoleOwner, "bootstrap", 0)
	if err != nil {
		return "", Key{}, err
	}
	if err := ks.PutKey(ctx, key); err != nil {
		return "", Key{}, err
	}
	return plaintext, key, nil
}
