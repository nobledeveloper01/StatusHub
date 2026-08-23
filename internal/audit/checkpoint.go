// Package audit verifies the hash chain and publishes signed checkpoints.
//
// A hash chain that nobody walks detects nothing. Tampering invalidates every
// record after the altered one — but only if somebody recomputes them, and
// only if what they recompute against is something the tamperer could not
// also have changed.
//
// That is what a checkpoint is for. Each night the chain is walked, and the
// head hash is signed and published. An attacker who alters a record must now
// also forge every checkpoint published since, which requires the signing key
// — held outside the database, so a full database compromise does not include
// it.
package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/metrics"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

// Checkpoint is a signed statement about a tenant's chain at a moment.
type Checkpoint struct {
	TenantID   string    `json:"tenant_id"`
	Records    int64     `json:"records"`
	HeadHash   string    `json:"head_hash"`
	Through    time.Time `json:"through"`
	VerifiedAt time.Time `json:"verified_at"`

	// Signature covers the fields above. Ed25519, so the public key can be
	// published and anybody — including the customer's own auditor — can
	// check a checkpoint without us being involved.
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`

	// Intact is false when the walk found a break. A failed verification is
	// still published and still signed: the record that the chain was broken
	// at a particular time is itself evidence, and suppressing it would be
	// the most useful thing an attacker could arrange.
	Intact   bool   `json:"intact"`
	BrokenAt string `json:"broken_at,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// signedPayload is the canonical form the signature covers. Built field by
// field rather than by marshalling the struct, because adding a field to the
// struct later must not silently change what old signatures verified against.
func (c Checkpoint) signedPayload() []byte {
	return []byte(fmt.Sprintf("statushub-checkpoint-v1|%s|%d|%s|%s|%t|%s",
		c.TenantID, c.Records, c.HeadHash,
		c.Through.UTC().Format(time.RFC3339Nano), c.Intact, c.BrokenAt))
}

// Signer produces and checks checkpoint signatures.
type Signer struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

// NewSigner builds a signer from a base64 seed. The seed lives in the secret
// manager, never in the database — the whole point is that a database
// compromise cannot forge a checkpoint.
func NewSigner(seedB64 string) (*Signer, error) {
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		return nil, fmt.Errorf("checkpoint signing seed is not valid base64: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("checkpoint signing seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Signer{private: priv, public: priv.Public().(ed25519.PublicKey)}, nil
}

// GenerateSigner creates a new key, returning the seed to store.
func GenerateSigner() (*Signer, string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, "", err
	}
	s, err := NewSigner(base64.StdEncoding.EncodeToString(seed))
	if err != nil {
		return nil, "", err
	}
	return s, base64.StdEncoding.EncodeToString(seed), nil
}

// PublicKey is published so anybody can verify a checkpoint.
func (s *Signer) PublicKey() string {
	return base64.StdEncoding.EncodeToString(s.public)
}

// Sign completes a checkpoint.
func (s *Signer) Sign(c Checkpoint) Checkpoint {
	c.PublicKey = s.PublicKey()
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, c.signedPayload()))
	return c
}

// VerifyCheckpoint checks a checkpoint against a published public key.
//
// A package-level function taking the key as an argument, deliberately: this
// is the code a customer's auditor runs, and it must not require any part of
// StatusHub's private state.
func VerifyCheckpoint(c Checkpoint, publicKeyB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return fmt.Errorf("public key is not valid base64: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(c.Signature)
	if err != nil {
		return fmt.Errorf("signature is not valid base64: %w", err)
	}
	if !ed25519.Verify(pub, c.signedPayload(), sig) {
		return errors.New("checkpoint signature does not verify against this public key")
	}
	return nil
}

// CheckpointStore persists checkpoints.
type CheckpointStore interface {
	PutCheckpoint(ctx context.Context, c Checkpoint) error
	LatestCheckpoint(ctx context.Context, tenantID string) (Checkpoint, error)
	ListCheckpoints(ctx context.Context, tenantID string, limit int) ([]Checkpoint, error)
}

// ErrNoCheckpoint is returned when a tenant has none yet.
var ErrNoCheckpoint = errors.New("no checkpoint for this tenant")

// MemoryCheckpointStore is the in-memory implementation.
type MemoryCheckpointStore struct {
	mu       sync.Mutex
	byTenant map[string][]Checkpoint
}

// NewMemoryCheckpointStore returns an empty store.
func NewMemoryCheckpointStore() *MemoryCheckpointStore {
	return &MemoryCheckpointStore{byTenant: map[string][]Checkpoint{}}
}

func (s *MemoryCheckpointStore) PutCheckpoint(_ context.Context, c Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byTenant[c.TenantID] = append(s.byTenant[c.TenantID], c)
	return nil
}

func (s *MemoryCheckpointStore) LatestCheckpoint(_ context.Context, tenantID string) (Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.byTenant[tenantID]
	if len(all) == 0 {
		return Checkpoint{}, ErrNoCheckpoint
	}
	return all[len(all)-1], nil
}

func (s *MemoryCheckpointStore) ListCheckpoints(_ context.Context, tenantID string, limit int) ([]Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.byTenant[tenantID]
	if limit <= 0 || limit > len(all) {
		limit = len(all)
	}
	out := make([]Checkpoint, 0, limit)
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, all[i])
	}
	return out, nil
}

// Verifier walks chains and publishes checkpoints.
type Verifier struct {
	store       store.Store
	checkpoints CheckpointStore
	signer      *Signer
	metrics     *metrics.Registry
	log         *slog.Logger
	now         func() time.Time
}

// VerifierOptions configure a Verifier.
type VerifierOptions struct {
	Store       store.Store
	Checkpoints CheckpointStore
	Signer      *Signer
	Metrics     *metrics.Registry
	Logger      *slog.Logger
	Now         func() time.Time
}

// NewVerifier builds a Verifier.
func NewVerifier(o VerifierOptions) *Verifier {
	v := &Verifier{
		store: o.Store, checkpoints: o.Checkpoints, signer: o.Signer,
		metrics: o.Metrics, log: o.Logger, now: o.Now,
	}
	if v.log == nil {
		v.log = slog.Default()
	}
	if v.metrics == nil {
		v.metrics = metrics.New()
	}
	if v.now == nil {
		v.now = func() time.Time { return time.Now().UTC() }
	}
	if v.checkpoints == nil {
		v.checkpoints = NewMemoryCheckpointStore()
	}
	return v
}

// VerifyTenant walks one tenant's chain and publishes a signed checkpoint.
func (v *Verifier) VerifyTenant(ctx context.Context, tenantID string) (Checkpoint, error) {
	proof, err := v.store.VerifyChain(ctx, tenantID)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("walking the chain for %s: %w", tenantID, err)
	}

	c := Checkpoint{
		TenantID: tenantID, Records: proof.Records, HeadHash: proof.Head,
		Through: proof.To, VerifiedAt: v.now(),
		Intact: proof.Intact, BrokenAt: proof.BrokenAt, Reason: proof.Reason,
	}

	// Continuity against the previous checkpoint is a second, independent
	// check. The chain walk proves the records are internally consistent;
	// this proves nobody rewrote history *between* two walks and left a chain
	// that is once again internally consistent — which a tamperer with write
	// access could otherwise do.
	if prev, err := v.checkpoints.LatestCheckpoint(ctx, tenantID); err == nil && prev.Intact {
		if proof.Records < prev.Records {
			c.Intact = false
			c.Reason = fmt.Sprintf(
				"the chain has %d records but the checkpoint at %s recorded %d; records have been removed",
				proof.Records, prev.VerifiedAt.Format(time.RFC3339), prev.Records)
		}
	}

	if v.signer != nil {
		c = v.signer.Sign(c)
	}

	// Published whether or not it verified. A failed verification is itself
	// evidence, and suppressing it is the most useful thing an attacker could
	// arrange.
	if err := v.checkpoints.PutCheckpoint(ctx, c); err != nil {
		return c, fmt.Errorf("storing the checkpoint for %s: %w", tenantID, err)
	}

	intact := 0.0
	if c.Intact {
		intact = 1
	}
	v.metrics.Set("statushub_audit_chain_intact", metrics.Labels{"tenant": tenantID}, intact)

	if !c.Intact {
		// This is a paging alert (§11.4). A broken audit chain is a security
		// incident, not a data-quality problem.
		v.log.ErrorContext(ctx, "audit chain verification FAILED",
			"tenant", tenantID, "records", c.Records,
			"broken_at", c.BrokenAt, "reason", c.Reason)
	}
	return c, nil
}

// Result summarises a nightly run.
type Result struct {
	VerifiedAt time.Time    `json:"verified_at"`
	Tenants    int          `json:"tenants"`
	Broken     []Checkpoint `json:"broken,omitempty"`
	Duration   string       `json:"duration"`
}

// VerifyAll walks every tenant's chain. This is the nightly job.
func (v *Verifier) VerifyAll(ctx context.Context) (Result, error) {
	start := v.now()
	res := Result{VerifiedAt: start}

	tenants, err := v.store.ListTenants(ctx)
	if err != nil {
		return res, err
	}
	sort.Slice(tenants, func(i, j int) bool { return tenants[i].ID < tenants[j].ID })

	for _, t := range tenants {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		c, err := v.VerifyTenant(ctx, t.ID)
		if err != nil {
			// One tenant's failure must not stop the others being checked:
			// the run exists to find problems, and stopping at the first
			// leaves every later tenant unverified.
			v.log.ErrorContext(ctx, "could not verify a tenant's audit chain",
				"tenant", t.ID, "error", err)
			continue
		}
		res.Tenants++
		if !c.Intact {
			res.Broken = append(res.Broken, c)
		}
	}
	res.Duration = v.now().Sub(start).Round(time.Millisecond).String()
	return res, nil
}

// Run is the nightly loop.
func (v *Verifier) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 24 * time.Hour
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		res, err := v.VerifyAll(ctx)
		switch {
		case err != nil:
			v.log.ErrorContext(ctx, "audit chain verification run failed", "error", err)
		case len(res.Broken) > 0:
			v.log.ErrorContext(ctx, "audit chain verification found broken chains",
				"tenants", res.Tenants, "broken", len(res.Broken))
		default:
			v.log.InfoContext(ctx, "audit chains verified",
				"tenants", res.Tenants, "duration", res.Duration)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Export renders a tenant's checkpoints for an auditor, with the public key
// and the instructions to check them independently.
func (v *Verifier) Export(ctx context.Context, tenantID string, limit int) ([]byte, error) {
	checkpoints, err := v.checkpoints.ListCheckpoints(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	pub := ""
	if v.signer != nil {
		pub = v.signer.PublicKey()
	}
	return json.MarshalIndent(map[string]any{
		"tenant_id":   tenantID,
		"public_key":  pub,
		"algorithm":   "ed25519",
		"checkpoints": checkpoints,
		"how_to_verify": "Each checkpoint's signature covers " +
			"\"statushub-checkpoint-v1|tenant_id|records|head_hash|through|intact|broken_at\". " +
			"Verify with the published ed25519 public key. A record altered after a checkpoint was " +
			"published would require forging every checkpoint since, which needs the private key — " +
			"and that is held outside the database.",
	}, "", "  ")
}
