package tests

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/secret"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

const (
	tenantA = "tnt_a"
	tenantB = "tnt_b"
	slugA   = "acme"
	slugB   = "globex"
)

// fixture reads a captured provider payload. Every adapter is tested against
// real payloads rather than against ones written from the documentation,
// because the gap between the two is precisely where adapters break (§11.9).
func fixture(t *testing.T, provider, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("fixtures", provider, name))
	if err != nil {
		t.Fatalf("reading fixture %s/%s: %v", provider, name, err)
	}
	return b
}

// memStore returns an in-memory store with two tenants already present, which
// is the shape every isolation test needs.
func memStore(t *testing.T) *store.Memory {
	t.Helper()
	s := store.NewMemory()
	ctx := context.Background()
	for _, tn := range []domain.Tenant{
		{ID: tenantA, Slug: slugA, Name: "Acme Payments", CreatedAt: time.Now().UTC()},
		{ID: tenantB, Slug: slugB, Name: "Globex Financial", CreatedAt: time.Now().UTC()},
	} {
		if err := s.CreateTenant(ctx, tn); err != nil {
			t.Fatalf("creating tenant %s: %v", tn.ID, err)
		}
	}
	return s
}

// staticSecrets returns a resolver holding one secret under one reference.
func staticSecrets(ref string, values ...string) *secret.Static {
	r := secret.NewStatic()
	r.Set(ref, values...)
	return r
}

func mustNoErr(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func mustErr(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an error, got none", what)
	}
}
