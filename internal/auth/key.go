// Package auth issues and checks API keys, and carries the authenticated
// tenant through a request (§8.2).
//
// This is layer one of the three-layer tenancy model (§8.1): a key resolves
// to exactly one tenant, and no key spans tenants. Ever. The other two layers
// are the repository interface, which takes tenantID as its first argument on
// every method, and Postgres row-level security, which returns nothing for a
// query that forgets to scope.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// Errors callers distinguish. The HTTP layer collapses all of them into one
// 401 with no detail — the distinction is for logs and metrics, not for the
// caller, who does not need to learn whether a key exists.
var (
	ErrNoKey      = errors.New("no API key presented")
	ErrMalformed  = errors.New("API key is malformed")
	ErrUnknownKey = errors.New("API key is not recognised")
	ErrRevoked    = errors.New("API key has been revoked")
	ErrExpired    = errors.New("API key has expired")
	ErrWrongEnv   = errors.New("API key is for a different environment")
	ErrForbidden  = errors.New("API key lacks the required role")
)

// Role is what a key or a user may do (§6.4).
type Role string

const (
	// RoleOwner can do everything, including issuing and revoking keys.
	RoleOwner Role = "owner"

	// RoleEngineer can change adapters, endpoints and destinations.
	RoleEngineer Role = "engineer"

	// RoleSupport can search events and replay deliveries but cannot change
	// an adapter. The split matters: replaying is the thing support staff
	// need hourly, and changing a mapping is the thing that silently alters
	// what every future event means.
	RoleSupport Role = "support"

	// RoleReadOnly can look and nothing else.
	RoleReadOnly Role = "read_only"
)

var roleRank = map[Role]int{
	RoleReadOnly: 1,
	RoleSupport:  2,
	RoleEngineer: 3,
	RoleOwner:    4,
}

// Valid reports whether r is a known role.
func (r Role) Valid() bool { _, ok := roleRank[r]; return ok }

// AtLeast reports whether r is as privileged as need.
func (r Role) AtLeast(need Role) bool { return roleRank[r] >= roleRank[need] }

func (r Role) String() string { return string(r) }

// Key is an issued API key as stored. The secret is not here and cannot be
// recovered from here.
type Key struct {
	ID       string
	TenantID string

	// Prefix is the first characters of the key, stored in plaintext. It is
	// how a presented key is looked up without scanning every row, and how
	// the dashboard shows which key is which without being able to show the
	// key.
	Prefix string

	// Hash is Argon2id over the secret half, with the parameters and salt
	// encoded alongside it, so the cost can be raised later without
	// invalidating existing keys.
	Hash string

	Environment domain.Environment
	Role        Role
	Name        string

	CreatedAt time.Time
	ExpiresAt time.Time
	LastUsed  time.Time
	RevokedAt time.Time
}

// Revoked reports whether the key has been revoked.
func (k *Key) Revoked() bool { return !k.RevokedAt.IsZero() }

// Expired reports whether the key is past its expiry.
func (k *Key) Expired(now time.Time) bool {
	return !k.ExpiresAt.IsZero() && now.After(k.ExpiresAt)
}

// Argon2id parameters.
//
// 64 MiB and one pass over four threads is the configuration OWASP
// recommends, and it costs a few tens of milliseconds. That is affordable
// here because a management API key is checked on management calls, which are
// rare — the receiver's hot path does not touch this code at all. Choosing
// parameters by what the busiest endpoint can afford is how password hashing
// ends up too weak to matter.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

var keyAlphabet = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// Issue creates a new key. The returned plaintext is the only time it exists
// anywhere; it is shown once and never retrievable (§8.2).
func Issue(tenantID string, env domain.Environment, role Role, name string, ttl time.Duration) (plaintext string, key Key, err error) {
	if !env.Valid() {
		return "", Key{}, fmt.Errorf("environment %q is not test or live", env)
	}
	if !role.Valid() {
		return "", Key{}, fmt.Errorf("role %q is not recognised", role)
	}

	var secret [24]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", Key{}, fmt.Errorf("entropy source unavailable: %w", err)
	}
	body := keyAlphabet.EncodeToString(secret[:])

	// sh_live_xxxxxxxx… The environment is in the key itself, so a live key
	// pasted into a test configuration is caught by inspection rather than by
	// its effects.
	plaintext = fmt.Sprintf("%s_%s_%s", domain.PrefixAPIKey, env, body)

	hash, err := hashSecret(body)
	if err != nil {
		return "", Key{}, err
	}

	now := time.Now().UTC()
	key = Key{
		ID:          domain.NewID("key"),
		TenantID:    tenantID,
		Prefix:      prefixOf(plaintext),
		Hash:        hash,
		Environment: env,
		Role:        role,
		Name:        name,
		CreatedAt:   now,
	}
	if ttl > 0 {
		key.ExpiresAt = now.Add(ttl)
	}
	return plaintext, key, nil
}

// PrefixLength is how much of a key is stored in the clear.
//
// Enough to look up and to display, short enough that the plaintext prefix is
// not itself a meaningful head start on guessing the rest — the remaining
// entropy after the prefix is still well over 100 bits.
const PrefixLength = 16

func prefixOf(plaintext string) string {
	if len(plaintext) <= PrefixLength {
		return plaintext
	}
	return plaintext[:PrefixLength]
}

// Parse splits a presented key into its lookup prefix and its secret half.
func Parse(presented string) (prefix, secret string, env domain.Environment, err error) {
	s := strings.TrimSpace(presented)
	s = strings.TrimPrefix(s, "Bearer ")
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", "", ErrNoKey
	}

	parts := strings.SplitN(s, "_", 3)
	if len(parts) != 3 || parts[0] != domain.PrefixAPIKey || parts[2] == "" {
		return "", "", "", ErrMalformed
	}
	env = domain.Environment(parts[1])
	if !env.Valid() {
		return "", "", "", ErrMalformed
	}
	return prefixOf(s), parts[2], env, nil
}

// Check verifies a presented secret against a stored key.
//
// The hash comparison runs whether or not the key is revoked or expired, and
// the state checks come afterwards. Returning early on a revoked key would
// make a revoked-key check measurably faster than a live-key check, which
// tells an attacker which of their stolen keys are still worth trying.
func Check(k *Key, secret string, now time.Time, env domain.Environment) error {
	ok, err := verifySecret(secret, k.Hash)
	if err != nil {
		return fmt.Errorf("stored key hash is unusable: %w", err)
	}
	switch {
	case !ok:
		return ErrUnknownKey
	case k.Revoked():
		return ErrRevoked
	case k.Expired(now):
		return ErrExpired
	case env != "" && k.Environment != env:
		// A leaked test key can do nothing to live data (§8.2).
		return ErrWrongEnv
	}
	return nil
}

func hashSecret(secret string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("entropy source unavailable: %w", err)
	}
	sum := argon2.IDKey([]byte(secret), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	// The parameters travel with the hash so raising the cost later does not
	// invalidate every key already issued.
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum)), nil
}

func verifySecret(secret, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false, errors.New("hash is not in the expected argon2id format")
	}
	var memory uint32
	var timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return false, fmt.Errorf("hash parameters are unreadable: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("hash salt is unreadable: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("hash digest is unreadable: %w", err)
	}
	got := argon2.IDKey([]byte(secret), salt, timeCost, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
