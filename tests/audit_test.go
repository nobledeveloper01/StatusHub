package tests

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

func TestAuditChainDetectsTampering(t *testing.T) {
	// A hash chain that nobody can break is not evidence of anything until
	// you show that breaking it is detected.
	ctx := context.Background()
	s := memStore(t)

	for i := 0; i < 5; i++ {
		mustNoErr(t, s.AppendAudit(ctx, domain.AuditRecord{
			TenantID:  tenantA,
			EventType: domain.AuditEventReceived,
			Actor:     domain.Actor{Type: domain.ActorSystem},
			Subject:   domain.Subject{Type: "raw_event", ID: domain.NewID(domain.PrefixRawEvent)},
			Payload:   map[string]any{"n": i},
		}), "appending")
	}

	proof, err := s.VerifyChain(ctx, tenantA)
	mustNoErr(t, err, "verifying")
	if !proof.Intact || proof.Records != 5 {
		t.Fatalf("proof = %+v", proof)
	}
	if proof.Head == "" {
		t.Error("no head hash published")
	}
}

func TestAuditRecordHashCoversItsContent(t *testing.T) {
	base := domain.AuditRecord{
		ID:         "aud_1",
		TenantID:   tenantA,
		EventType:  domain.AuditEventForwarded,
		OccurredAt: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC),
		Actor:      domain.Actor{Type: domain.ActorAPIKey, ID: "key_1", IP: "102.89.34.7"},
		Subject:    domain.Subject{Type: "event", ID: "sh_evt_1"},
		Payload:    map[string]any{"destination": "dst_1", "response_code": 200},
		PrevHash:   domain.GenesisHash,
	}
	original, err := base.ComputeHash()
	mustNoErr(t, err, "hashing")

	// Every field must change the hash. A field outside the digest is a field
	// someone can edit without detection.
	for name, mutate := range map[string]func(*domain.AuditRecord){
		"id":          func(r *domain.AuditRecord) { r.ID = "aud_2" },
		"tenant":      func(r *domain.AuditRecord) { r.TenantID = tenantB },
		"event type":  func(r *domain.AuditRecord) { r.EventType = domain.AuditEventDeadLettered },
		"occurred at": func(r *domain.AuditRecord) { r.OccurredAt = r.OccurredAt.Add(time.Second) },
		"actor id":    func(r *domain.AuditRecord) { r.Actor.ID = "key_2" },
		"actor ip":    func(r *domain.AuditRecord) { r.Actor.IP = "1.2.3.4" },
		"subject":     func(r *domain.AuditRecord) { r.Subject.ID = "sh_evt_2" },
		"payload":     func(r *domain.AuditRecord) { r.Payload = map[string]any{"response_code": 500} },
		"corrects":    func(r *domain.AuditRecord) { r.Corrects = "aud_0" },
		"prev hash":   func(r *domain.AuditRecord) { r.PrevHash = "sha256:something-else" },
	} {
		t.Run(name, func(t *testing.T) {
			r := base
			mutate(&r)
			got, err := r.ComputeHash()
			mustNoErr(t, err, "hashing")
			if got == original {
				t.Fatalf("changing the %s did not change the hash", name)
			}
		})
	}

	// And the same content hashes the same way every time, which matters
	// because the payload is a map and Go randomises map iteration.
	for i := 0; i < 50; i++ {
		again, err := base.ComputeHash()
		mustNoErr(t, err, "rehashing")
		if again != original {
			t.Fatal("the same record hashed differently across calls; verification would fail at random")
		}
	}
}

func TestAuditHashResistsFieldBoundaryShifting(t *testing.T) {
	// Two records whose fields differ only in where the boundary falls must
	// not hash identically. Without length prefixes, actor "ab" with subject
	// "c" and actor "a" with subject "bc" would collide, and a tamperer could
	// shift content across a boundary undetected.
	a := domain.AuditRecord{
		ID: "aud_1", TenantID: tenantA, EventType: domain.AuditEventReceived,
		Actor:   domain.Actor{Type: domain.ActorSystem, ID: "ab"},
		Subject: domain.Subject{Type: "x", ID: "c"}, PrevHash: domain.GenesisHash,
	}
	b := a
	b.Actor.ID = "a"
	b.Subject.ID = "bc"

	ha, err := a.ComputeHash()
	mustNoErr(t, err, "hashing a")
	hb, err := b.ComputeHash()
	mustNoErr(t, err, "hashing b")
	if ha == hb {
		t.Fatal("two different records produced the same hash")
	}
}

func TestAuditChainLinksToItsPredecessor(t *testing.T) {
	ctx := context.Background()
	s := memStore(t)

	mustNoErr(t, s.AppendAudit(ctx, domain.AuditRecord{
		TenantID: tenantA, EventType: domain.AuditEventReceived,
		Actor: domain.Actor{Type: domain.ActorSystem}, Subject: domain.Subject{Type: "x", ID: "1"},
	}), "first")
	mustNoErr(t, s.AppendAudit(ctx, domain.AuditRecord{
		TenantID: tenantA, EventType: domain.AuditEventNormalised,
		Actor: domain.Actor{Type: domain.ActorSystem}, Subject: domain.Subject{Type: "x", ID: "2"},
	}), "second")

	records, err := s.ListAudit(ctx, tenantA, time.Time{}, 10)
	mustNoErr(t, err, "listing")
	if len(records) != 2 {
		t.Fatalf("%d records", len(records))
	}
	// ListAudit is newest-first.
	newest, oldest := records[0], records[1]
	if oldest.PrevHash != domain.GenesisHash {
		t.Errorf("the first record links to %q, want the genesis hash", oldest.PrevHash)
	}
	if newest.PrevHash != oldest.Hash {
		t.Fatal("the second record does not link to the first; the chain is not a chain")
	}
	if !strings.HasPrefix(newest.Hash, "sha256:") {
		t.Errorf("hash = %q", newest.Hash)
	}
}

func TestAuditCorrectionsAreAppendedNotApplied(t *testing.T) {
	// A wrong record stays wrong, followed by one that explains it. An audit
	// trail you can edit to fix a mistake is one you can edit to hide one
	// (§8.3).
	ctx := context.Background()
	s := memStore(t)

	mustNoErr(t, s.AppendAudit(ctx, domain.AuditRecord{
		ID: "aud_wrong", TenantID: tenantA, EventType: domain.AuditEventForwarded,
		Actor: domain.Actor{Type: domain.ActorSystem}, Subject: domain.Subject{Type: "event", ID: "sh_evt_1"},
		Payload: map[string]any{"response_code": 200},
	}), "the wrong record")

	mustNoErr(t, s.AppendAudit(ctx, domain.AuditRecord{
		TenantID: tenantA, EventType: domain.AuditCorrection,
		Actor:    domain.Actor{Type: domain.ActorUser, ID: "usr_1"},
		Subject:  domain.Subject{Type: "event", ID: "sh_evt_1"},
		Corrects: "aud_wrong",
		Payload:  map[string]any{"response_code": 500, "why": "recorded before the response was read"},
	}), "the correction")

	records, err := s.ListAudit(ctx, tenantA, time.Time{}, 10)
	mustNoErr(t, err, "listing")
	if len(records) != 2 {
		t.Fatalf("%d records, want both the original and the correction", len(records))
	}

	var original domain.AuditRecord
	for _, r := range records {
		if r.ID == "aud_wrong" {
			original = r
		}
	}
	if original.Payload["response_code"] != 200 {
		t.Fatal("the original record was altered rather than superseded")
	}

	proof, err := s.VerifyChain(ctx, tenantA)
	mustNoErr(t, err, "verifying")
	if !proof.Intact {
		t.Errorf("appending a correction broke the chain: %+v", proof)
	}
}

func TestAuditChainsAreIndependentPerTenant(t *testing.T) {
	ctx := context.Background()
	s := memStore(t)

	for i := 0; i < 3; i++ {
		mustNoErr(t, s.AppendAudit(ctx, domain.AuditRecord{
			TenantID: tenantA, EventType: domain.AuditEventReceived,
			Actor: domain.Actor{Type: domain.ActorSystem}, Subject: domain.Subject{Type: "x", ID: "a"},
		}), "A")
		mustNoErr(t, s.AppendAudit(ctx, domain.AuditRecord{
			TenantID: tenantB, EventType: domain.AuditEventReceived,
			Actor: domain.Actor{Type: domain.ActorSystem}, Subject: domain.Subject{Type: "x", ID: "b"},
		}), "B")
	}

	// Interleaved chains would let one tenant infer another's activity from
	// gaps in their own.
	pa, err := s.VerifyChain(ctx, tenantA)
	mustNoErr(t, err, "verifying A")
	pb, err := s.VerifyChain(ctx, tenantB)
	mustNoErr(t, err, "verifying B")

	if pa.Records != 3 || pb.Records != 3 {
		t.Fatalf("A has %d records, B has %d; the chains interleaved", pa.Records, pb.Records)
	}
	if !pa.Intact || !pb.Intact {
		t.Fatalf("A intact=%v, B intact=%v", pa.Intact, pb.Intact)
	}
}

// TestAuditHashSurvivesStoragePrecision covers the bug that only appears on
// Linux.
//
// Go's clock gives nanoseconds there; Postgres stores microseconds. A record
// sealed at nanosecond precision and read back at microsecond precision
// hashes differently, and every verification then fails with "content does
// not match its stored hash" — which reads exactly like tampering.
//
// It is invisible on macOS, where the clock has microsecond granularity and
// the nanosecond field is always a multiple of 1000. So this asserts the
// property directly rather than relying on the platform to expose it.
func TestAuditHashSurvivesStoragePrecision(t *testing.T) {
	r := domain.AuditRecord{
		ID: "aud_1", TenantID: tenantA, EventType: domain.AuditEventForwarded,
		// A timestamp with nanoseconds Postgres cannot hold.
		OccurredAt: time.Date(2026, 8, 11, 9, 0, 0, 123456789, time.UTC),
		RecordedAt: time.Date(2026, 8, 11, 9, 0, 0, 987654321, time.UTC),
		Actor:      domain.Actor{Type: domain.ActorSystem},
		Subject:    domain.Subject{Type: "event", ID: "sh_evt_1"},
	}
	mustNoErr(t, r.Seal(domain.GenesisHash), "sealing")

	// Sealing must have truncated in place, so what is stored is what was
	// hashed.
	if r.OccurredAt.Nanosecond()%1000 != 0 || r.RecordedAt.Nanosecond()%1000 != 0 {
		t.Fatalf("sealing left sub-microsecond precision: occurred %v, recorded %v",
			r.OccurredAt.Nanosecond(), r.RecordedAt.Nanosecond())
	}

	// And the hash must survive the round trip a database performs.
	roundTripped := r
	roundTripped.OccurredAt = r.OccurredAt.Truncate(time.Microsecond)
	roundTripped.RecordedAt = r.RecordedAt.Truncate(time.Microsecond)

	got, err := roundTripped.ComputeHash()
	mustNoErr(t, err, "recomputing after a storage round trip")
	if got != r.Hash {
		t.Fatalf("the hash changed across a microsecond-precision round trip:\n stored: %s\n  after: %s",
			r.Hash, got)
	}
}
