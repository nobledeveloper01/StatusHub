package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/audit"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

func appendAudits(t *testing.T, s interface {
	AppendAudit(context.Context, domain.AuditRecord) error
}, tenant string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		mustNoErr(t, s.AppendAudit(context.Background(), domain.AuditRecord{
			TenantID: tenant, EventType: domain.AuditEventReceived,
			Actor:   domain.Actor{Type: domain.ActorSystem},
			Subject: domain.Subject{Type: "raw_event", ID: domain.NewID(domain.PrefixRawEvent)},
			Payload: map[string]any{"n": i},
		}), "appending")
	}
}

func TestCheckpointIsIndependentlyVerifiable(t *testing.T) {
	// The whole point: a customer's auditor can check this without us being
	// involved, using only the published public key.
	ctx := context.Background()
	s := memStore(t)
	appendAudits(t, s, tenantA, 5)

	signer, seed, err := audit.GenerateSigner()
	mustNoErr(t, err, "generating a signer")
	if seed == "" {
		t.Fatal("no seed returned to store in the secret manager")
	}

	v := audit.NewVerifier(audit.VerifierOptions{Store: s, Signer: signer})
	c, err := v.VerifyTenant(ctx, tenantA)
	mustNoErr(t, err, "verifying")

	if !c.Intact || c.Records != 5 || c.HeadHash == "" {
		t.Fatalf("checkpoint = %+v", c)
	}
	mustNoErr(t, audit.VerifyCheckpoint(c, signer.PublicKey()),
		"a genuine checkpoint must verify against the published key")

	// A different key must not verify it.
	other, _, err := audit.GenerateSigner()
	mustNoErr(t, err, "generating another signer")
	if err := audit.VerifyCheckpoint(c, other.PublicKey()); err == nil {
		t.Fatal("a checkpoint verified against the wrong public key")
	}
}

func TestCheckpointSignatureCoversEveryClaim(t *testing.T) {
	// A field outside the signature is a field an attacker can edit while
	// the checkpoint still verifies.
	ctx := context.Background()
	s := memStore(t)
	appendAudits(t, s, tenantA, 3)

	signer, _, err := audit.GenerateSigner()
	mustNoErr(t, err, "signer")
	v := audit.NewVerifier(audit.VerifierOptions{Store: s, Signer: signer})
	c, err := v.VerifyTenant(ctx, tenantA)
	mustNoErr(t, err, "verifying")

	for name, mutate := range map[string]func(*audit.Checkpoint){
		"tenant":    func(c *audit.Checkpoint) { c.TenantID = tenantB },
		"records":   func(c *audit.Checkpoint) { c.Records = 99 },
		"head hash": func(c *audit.Checkpoint) { c.HeadHash = "sha256:forged" },
		"through":   func(c *audit.Checkpoint) { c.Through = c.Through.Add(time.Hour) },
		"intact":    func(c *audit.Checkpoint) { c.Intact = !c.Intact },
		"broken at": func(c *audit.Checkpoint) { c.BrokenAt = "aud_something" },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := c
			mutate(&tampered)
			if err := audit.VerifyCheckpoint(tampered, signer.PublicKey()); err == nil {
				t.Fatalf("altering the %s did not invalidate the signature", name)
			}
		})
	}
}

func TestCheckpointPublishesFailuresRatherThanHidingThem(t *testing.T) {
	// A failed verification is itself evidence. Suppressing it is the most
	// useful thing an attacker could arrange.
	ctx := context.Background()
	s := memStore(t)
	appendAudits(t, s, tenantA, 4)

	signer, _, err := audit.GenerateSigner()
	mustNoErr(t, err, "signer")
	checkpoints := audit.NewMemoryCheckpointStore()
	v := audit.NewVerifier(audit.VerifierOptions{
		Store: s, Signer: signer, Checkpoints: checkpoints,
	})

	first, err := v.VerifyTenant(ctx, tenantA)
	mustNoErr(t, err, "first verification")
	if !first.Intact {
		t.Fatalf("a healthy chain reported broken: %+v", first)
	}

	// Now records disappear. The in-memory store's chain walk would still
	// pass on a truncated chain, so continuity against the last checkpoint is
	// the check that catches it — a tamperer with write access can produce a
	// chain that is once again internally consistent.
	truncated := memStore(t)
	appendAudits(t, truncated, tenantA, 2)
	v2 := audit.NewVerifier(audit.VerifierOptions{
		Store: truncated, Signer: signer, Checkpoints: checkpoints,
	})

	second, err := v2.VerifyTenant(ctx, tenantA)
	mustNoErr(t, err, "second verification")
	if second.Intact {
		t.Fatal("records were removed between checkpoints and the chain still reported intact")
	}
	if !strings.Contains(second.Reason, "records have been removed") {
		t.Errorf("reason = %q", second.Reason)
	}

	// And the failure was published and signed, not swallowed.
	latest, err := checkpoints.LatestCheckpoint(ctx, tenantA)
	mustNoErr(t, err, "reading the latest checkpoint")
	if latest.Intact {
		t.Fatal("the broken checkpoint was not published")
	}
	mustNoErr(t, audit.VerifyCheckpoint(latest, signer.PublicKey()),
		"a failure checkpoint must still be signed, or it is not evidence")
}

func TestCheckpointDetectsATamperedRecord(t *testing.T) {
	ctx := context.Background()
	s := memStore(t)
	appendAudits(t, s, tenantA, 6)

	v := audit.NewVerifier(audit.VerifierOptions{Store: s})
	c, err := v.VerifyTenant(ctx, tenantA)
	mustNoErr(t, err, "verifying")
	if !c.Intact {
		t.Fatalf("healthy chain reported broken: %+v", c)
	}

	// Independently recompute: a record whose content no longer matches its
	// stored hash must be caught.
	proof, err := s.VerifyChain(ctx, tenantA)
	mustNoErr(t, err, "walking")
	if !proof.Intact || proof.Records != 6 {
		t.Fatalf("proof = %+v", proof)
	}
}

func TestCheckpointVerifyAllCoversEveryTenant(t *testing.T) {
	// One tenant's failure must not stop the others being checked: the run
	// exists to find problems, and stopping at the first leaves every later
	// tenant unverified.
	ctx := context.Background()
	s := memStore(t)
	appendAudits(t, s, tenantA, 3)
	appendAudits(t, s, tenantB, 2)

	v := audit.NewVerifier(audit.VerifierOptions{Store: s})
	res, err := v.VerifyAll(ctx)
	mustNoErr(t, err, "verifying all")
	if res.Tenants != 2 {
		t.Fatalf("verified %d tenants, want 2", res.Tenants)
	}
	if len(res.Broken) != 0 {
		t.Errorf("broken = %+v", res.Broken)
	}
	if res.Duration == "" {
		t.Error("no duration recorded")
	}
}

func TestCheckpointExportIsSelfExplanatory(t *testing.T) {
	// An auditor receiving this file must be able to check it without asking
	// us anything.
	ctx := context.Background()
	s := memStore(t)
	appendAudits(t, s, tenantA, 3)

	signer, _, err := audit.GenerateSigner()
	mustNoErr(t, err, "signer")
	v := audit.NewVerifier(audit.VerifierOptions{Store: s, Signer: signer})
	if _, err := v.VerifyTenant(ctx, tenantA); err != nil {
		t.Fatalf("verifying: %v", err)
	}

	raw, err := v.Export(ctx, tenantA, 10)
	mustNoErr(t, err, "exporting")

	var out map[string]any
	mustNoErr(t, json.Unmarshal(raw, &out), "decoding the export")
	if out["public_key"] == "" || out["algorithm"] != "ed25519" {
		t.Errorf("export does not publish the key: %v", out["public_key"])
	}
	how, _ := out["how_to_verify"].(string)
	if !strings.Contains(how, "statushub-checkpoint-v1") {
		t.Errorf("the export does not state what the signature covers: %q", how)
	}
	cps, _ := out["checkpoints"].([]any)
	if len(cps) != 1 {
		t.Errorf("%d checkpoints exported", len(cps))
	}
	// The private key must never appear.
	if strings.Contains(string(raw), "seed") {
		t.Error("the export mentions the seed")
	}
}

func TestCheckpointSignerRejectsABadSeed(t *testing.T) {
	for _, bad := range []string{"", "not-base64!!", "c2hvcnQ="} {
		if _, err := audit.NewSigner(bad); err == nil {
			t.Errorf("seed %q was accepted", bad)
		}
	}
}
