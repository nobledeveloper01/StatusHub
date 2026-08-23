package tests

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/auth"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

func TestAuthKeyIsNotRecoverableFromWhatIsStored(t *testing.T) {
	plaintext, key, err := auth.Issue(tenantA, domain.EnvLive, auth.RoleEngineer, "ci", 0)
	mustNoErr(t, err, "issuing")

	// Everything stored must be useless to anyone who steals the database.
	if strings.Contains(key.Hash, plaintext) {
		t.Fatal("the stored hash contains the key")
	}
	secret := strings.SplitN(plaintext, "_", 3)[2]
	if strings.Contains(key.Hash, secret) {
		t.Fatal("the stored hash contains the key's secret half")
	}
	// The prefix is deliberately plaintext — it is the lookup, and how the
	// dashboard shows which key is which — but it must not be most of the key.
	if len(key.Prefix) >= len(plaintext)/2 {
		t.Errorf("the stored prefix is %d of %d characters, which is too much of the key", len(key.Prefix), len(plaintext))
	}
	if !strings.HasPrefix(key.Hash, "argon2id$") {
		t.Errorf("hash is not argon2id: %q", key.Hash)
	}
	// Parameters travel with the hash, so the cost can be raised later
	// without invalidating every key already issued.
	if !strings.Contains(key.Hash, "m=") || !strings.Contains(key.Hash, "t=") || !strings.Contains(key.Hash, "p=") {
		t.Errorf("hash does not carry its parameters: %q", key.Hash)
	}
}

func TestAuthKeyNamesItsEnvironment(t *testing.T) {
	// A live key pasted into a test configuration should be catchable by
	// inspection, not only by its effects.
	live, _, err := auth.Issue(tenantA, domain.EnvLive, auth.RoleOwner, "", 0)
	mustNoErr(t, err, "issuing live")
	test, _, err := auth.Issue(tenantA, domain.EnvTest, auth.RoleOwner, "", 0)
	mustNoErr(t, err, "issuing test")

	if !strings.HasPrefix(live, "sh_live_") {
		t.Errorf("live key = %q", live[:12])
	}
	if !strings.HasPrefix(test, "sh_test_") {
		t.Errorf("test key = %q", test[:12])
	}
}

func TestAuthCheckRejectsTheRightThings(t *testing.T) {
	now := time.Now().UTC()
	plaintext, key, err := auth.Issue(tenantA, domain.EnvLive, auth.RoleEngineer, "ci", time.Hour)
	mustNoErr(t, err, "issuing")
	_, secret, env, err := auth.Parse(plaintext)
	mustNoErr(t, err, "parsing")

	mustNoErr(t, auth.Check(&key, secret, now, env), "a genuine key")

	if err := auth.Check(&key, "wrong-secret", now, env); !errors.Is(err, auth.ErrUnknownKey) {
		t.Errorf("a wrong secret gave %v", err)
	}

	// A leaked test key can do nothing to live data (§8.2).
	if err := auth.Check(&key, secret, now, domain.EnvTest); !errors.Is(err, auth.ErrWrongEnv) {
		t.Errorf("a live key was accepted for the test environment: %v", err)
	}

	if err := auth.Check(&key, secret, now.Add(2*time.Hour), env); !errors.Is(err, auth.ErrExpired) {
		t.Errorf("an expired key was accepted: %v", err)
	}

	revoked := key
	revoked.RevokedAt = now
	if err := auth.Check(&revoked, secret, now, env); !errors.Is(err, auth.ErrRevoked) {
		t.Errorf("a revoked key was accepted: %v", err)
	}
	// And a revoked key with the wrong secret is reported as unknown, not as
	// revoked: the hash comparison runs first, so a revoked-key check is not
	// measurably faster than a live-key check.
	if err := auth.Check(&revoked, "wrong", now, env); !errors.Is(err, auth.ErrUnknownKey) {
		t.Errorf("a revoked key with a wrong secret leaked its state: %v", err)
	}
}

func TestAuthRoleHierarchy(t *testing.T) {
	cases := []struct {
		have, need auth.Role
		want       bool
	}{
		{auth.RoleOwner, auth.RoleEngineer, true},
		{auth.RoleOwner, auth.RoleOwner, true},
		{auth.RoleEngineer, auth.RoleSupport, true},
		{auth.RoleEngineer, auth.RoleOwner, false},
		{auth.RoleSupport, auth.RoleReadOnly, true},
		// The split that matters: support can replay, and cannot touch an
		// adapter (§6.4).
		{auth.RoleSupport, auth.RoleEngineer, false},
		{auth.RoleReadOnly, auth.RoleSupport, false},
	}
	for _, c := range cases {
		if got := c.have.AtLeast(c.need); got != c.want {
			t.Errorf("%s.AtLeast(%s) = %v, want %v", c.have, c.need, got, c.want)
		}
	}
}

func TestAuthNoIdentityIsAnError(t *testing.T) {
	// A route that reaches a handler without passing through the middleware
	// is a route that forgot to be protected. It must fail loudly rather than
	// default to anything.
	if _, err := auth.FromContext(context.Background()); !errors.Is(err, auth.ErrNoIdentity) {
		t.Fatalf("an unauthenticated context produced %v", err)
	}
	if _, err := auth.MustTenant(context.Background()); err == nil {
		t.Fatal("MustTenant returned a tenant for an unauthenticated context")
	}
}

func TestAuthKeysAreUnique(t *testing.T) {
	// Forty rather than a few thousand: each Issue runs Argon2id at the
	// production cost, which is deliberately expensive, and a uniqueness test
	// that adds a minute to every CI run is a test people start skipping.
	seen := map[string]struct{}{}
	for i := 0; i < 40; i++ {
		p, k, err := auth.Issue(tenantA, domain.EnvLive, auth.RoleReadOnly, "", 0)
		mustNoErr(t, err, "issuing")
		if _, clash := seen[p]; clash {
			t.Fatal("two issued keys were identical")
		}
		if _, clash := seen[k.Prefix]; clash {
			// Prefix collisions would make lookup ambiguous. With 120 bits
			// after the prefix this should never happen, and "should never"
			// is worth asserting.
			t.Fatal("two issued keys shared a lookup prefix")
		}
		seen[p], seen[k.Prefix] = struct{}{}, struct{}{}
	}
}

func TestAuthBootstrapIssuesAnOwnerKey(t *testing.T) {
	ctx := context.Background()
	ks := auth.NewMemoryKeyStore()
	plaintext, key, err := auth.Bootstrap(ctx, ks, tenantA, domain.EnvLive)
	mustNoErr(t, err, "bootstrapping")

	if key.Role != auth.RoleOwner {
		t.Errorf("bootstrap role = %q", key.Role)
	}
	stored, err := ks.GetKeyByPrefix(ctx, key.Prefix)
	mustNoErr(t, err, "looking the key up")
	_, secret, env, err := auth.Parse(plaintext)
	mustNoErr(t, err, "parsing")
	mustNoErr(t, auth.Check(&stored, secret, time.Now().UTC(), env), "the bootstrap key should work")
}
