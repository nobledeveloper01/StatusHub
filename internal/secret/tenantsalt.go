package secret

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// TenantSaltScheme is the reference prefix the normaliser asks for when it
// needs a tenant's pseudonymisation salt.
const TenantSaltScheme = "tenant-salt"

// TenantSalt derives a per-tenant salt from one master secret.
//
// The alternative — provisioning a distinct salt per tenant — is what the
// first version of this did, and it has a failure mode that is quiet and
// total: a tenant whose salt was never provisioned has every customer
// reference silently dropped and every event flagged incomplete. Nothing
// errors, nothing pages, and the gap is only visible if somebody notices the
// flag on a screen they had no reason to open.
//
// Deriving removes the provisioning step entirely. One master secret exists,
// and every tenant's salt follows from it. The properties that matter are
// preserved:
//
//   - Per-tenant separation. HKDF with the tenant ID as info means two
//     tenants hashing the same email produce different values, so one
//     tenant's leaked data cannot correlate a person across another's.
//   - Irreversibility. The salt cannot be worked backwards to the master, so
//     a compromised salt does not compromise every other tenant.
//   - Stability. The same tenant always derives the same salt, which matters
//     because a salt that changed would orphan every hash already stored and
//     make an erasure request match nothing.
//
// What it costs is that rotating the master re-derives every salt at once,
// which orphans existing hashes. That is a deliberate, documented, rare
// operation — and the erasure tooling names the old salt explicitly so a
// rotation does not silently break the ability to honour a deletion request.
type TenantSalt struct {
	master []byte
}

// NewTenantSalt builds a deriver from a base64 master secret.
func NewTenantSalt(masterB64 string) (*TenantSalt, error) {
	master, err := base64.StdEncoding.DecodeString(strings.TrimSpace(masterB64))
	if err != nil {
		return nil, fmt.Errorf("tenant salt master is not valid base64: %w", err)
	}
	if len(master) < 32 {
		// A short master would make every derived salt weak, and this is the
		// one input whose weakness would not show up anywhere.
		return nil, fmt.Errorf("tenant salt master must be at least 32 bytes, got %d", len(master))
	}
	return &TenantSalt{master: master}, nil
}

// Resolve derives the salt for a `tenant-salt://<tenant-id>` reference.
func (t *TenantSalt) Resolve(_ context.Context, ref string) (string, error) {
	tenantID, ok := strings.CutPrefix(ref, TenantSaltScheme+"://")
	if !ok || tenantID == "" {
		return "", fmt.Errorf("%w: %q is not a %s reference", ErrBadReference, ref, TenantSaltScheme)
	}

	salt, err := hkdf.Key(sha256.New, t.master, nil,
		// The purpose string is part of the derivation, so a future use of
		// the same master for something else cannot produce the same key.
		"statushub/pseudonymisation-salt/v1/"+tenantID, 32)
	if err != nil {
		return "", fmt.Errorf("deriving the salt for %s: %w", tenantID, err)
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// ResolveAll returns the single derived salt.
//
// Deliberately one value rather than an overlap window. A salt with two valid
// values would produce two different hashes for one person, which defeats the
// correlation the hash exists for — and would make an erasure request match
// half their events.
func (t *TenantSalt) ResolveAll(ctx context.Context, ref string) ([]string, error) {
	v, err := t.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	return []string{v}, nil
}

// ErrNoMaster means no master secret was configured.
var ErrNoMaster = errors.New("no tenant salt master is configured, so customer references cannot be pseudonymised")
