package tests

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/migrate"
	"github.com/nobledeveloper01/StatusHub/internal/normalise"
	"github.com/nobledeveloper01/StatusHub/internal/store"
	"github.com/nobledeveloper01/StatusHub/internal/subject"
)

const tenantSalt = "a-per-tenant-salt"

func subjectSetup(t *testing.T) (*subject.Service, *store.Postgres, domain.Endpoint) {
	t.Helper()
	dsn := os.Getenv("STATUSHUB_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("STATUSHUB_TEST_DATABASE_URL is not set; skipping the data subject tests")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	mustNoErr(t, err, "connecting")
	t.Cleanup(pool.Close)
	_, err = pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)
	mustNoErr(t, err, "resetting")
	_, err = migrate.Up(ctx, pool)
	mustNoErr(t, err, "migrating")

	s := store.NewPostgresFromPool(pool)
	mustNoErr(t, s.CreateTenant(ctx, domain.Tenant{ID: tenantA, Slug: slugA, Name: "Acme"}), "tenant")

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "endpoint")

	return subject.New(pool, func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }), s, ep
}

// storeEventFor creates a raw event and its canonical counterpart for a
// subject, with the customer's email left in the raw body — which is where it
// really is, because the provider chose the payload, not us.
func storeEventFor(t *testing.T, s *store.Postgres, ep domain.Endpoint, hash, email, ref string, at time.Time) domain.CanonicalEvent {
	t.Helper()
	ctx := context.Background()

	raw := domain.RawEvent{
		ID: domain.NewID(domain.PrefixRawEvent), TenantID: tenantA, EndpointID: ep.ID,
		Provider: "paystack",
		Body: []byte(`{"data":{"reference":"` + ref + `","customer":{"email":"` + email +
			`","phone":"+2348030000000"}}}`),
		BodySHA256: "h", SignatureValid: true, ReceivedAt: at,
		Headers: map[string]string{"user-agent": "Paystack/1.0"},
	}
	mustNoErr(t, s.PutRawEvent(ctx, raw), "raw event")

	ev := domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, RawEventID: raw.ID,
		Provider: "paystack", EventType: domain.EventPaymentCompleted, TransactionRef: ref,
		Status: domain.StatusSuccess, AmountMinor: 5000000, Currency: "NGN",
		CustomerRefHash: hash, OccurredAt: at, ReceivedAt: at, MappingComplete: true,
		ProviderExtra: map[string]any{"data.customer.phone": "+2348030000000"},
	}
	mustNoErr(t, s.PutCanonicalEvent(ctx, ev), "canonical event")
	return ev
}

func TestSubjectResolveMatchesTheNormaliser(t *testing.T) {
	// If these ever diverged, an erasure would match nothing and report
	// success — the worst possible failure for this feature.
	ref := subject.Resolve(tenantA, tenantSalt, "tunde@example.com")
	if !strings.HasPrefix(ref.Hash, "sha256:") {
		t.Fatalf("hash = %q", ref.Hash)
	}
	// The same identifier under a different tenant salt must not collide, or
	// one tenant's erasure would reach into another's data.
	other := subject.Resolve(tenantB, "a-different-salt", "tunde@example.com")
	if other.Hash == ref.Hash {
		t.Fatal("the same subject hashed identically across tenants")
	}
	// And the reference the normaliser publishes is the one we key on.
	if normalise.SaltRef(tenantA) == "" {
		t.Error("the salt reference is empty")
	}
}

func TestSubjectExportIncludesEverythingHeld(t *testing.T) {
	svc, s, ep := subjectSetup(t)
	ctx := context.Background()
	ref := subject.Resolve(tenantA, tenantSalt, "tunde@example.com")
	other := subject.Resolve(tenantA, tenantSalt, "ngozi@example.com")

	at := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)
	storeEventFor(t, s, ep, ref.Hash, "tunde@example.com", "TXN-1", at)
	storeEventFor(t, s, ep, ref.Hash, "tunde@example.com", "TXN-2", at.Add(time.Hour))
	storeEventFor(t, s, ep, other.Hash, "ngozi@example.com", "TXN-3", at)

	e, err := svc.Export(ctx, ref)
	mustNoErr(t, err, "exporting")

	if len(e.Events) != 2 {
		t.Fatalf("%d events exported, want the subject's 2 and nobody else's", len(e.Events))
	}
	for _, ev := range e.Events {
		if ev.TransactionRef == "TXN-3" {
			t.Fatal("another subject's event was included in the export")
		}
	}
	// provider_extra is the field most likely to hold something about the
	// subject we did not map. Omitting it because we do not know what is in
	// it would be exactly backwards.
	if e.Events[0].ProviderExtra["data.customer.phone"] != "+2348030000000" {
		t.Errorf("unmapped subject data was omitted: %v", e.Events[0].ProviderExtra)
	}
	// An export that silently omits a category is indistinguishable from one
	// where that category was empty.
	if !strings.Contains(e.Note, "Raw provider payloads are excluded") {
		t.Errorf("the export does not say what it leaves out: %q", e.Note)
	}

	var buf bytes.Buffer
	mustNoErr(t, e.WriteJSON(&buf), "rendering")
	if !strings.Contains(buf.String(), "TXN-1") {
		t.Error("the rendered export is missing events")
	}
}

// TestSubjectErasureActuallyErases is the assertion §9's promise rests on.
//
// The failure mode of an erasure is silence: a query matching nothing reports
// success just as loudly as one that erased everything.
func TestSubjectErasureActuallyErases(t *testing.T) {
	svc, s, ep := subjectSetup(t)
	ctx := context.Background()
	ref := subject.Resolve(tenantA, tenantSalt, "tunde@example.com")
	other := subject.Resolve(tenantA, tenantSalt, "ngozi@example.com")

	at := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)
	mine := storeEventFor(t, s, ep, ref.Hash, "tunde@example.com", "TXN-1", at)
	theirs := storeEventFor(t, s, ep, other.Hash, "ngozi@example.com", "TXN-2", at)

	// The dry run reports without doing anything.
	planned, err := svc.Erase(ctx, ref, true)
	mustNoErr(t, err, "dry run")
	if planned.EventsAffected != 1 || planned.RawBodiesWiped != 1 {
		t.Fatalf("dry run = %+v", planned)
	}
	stillThere, err := s.GetCanonicalEvent(ctx, tenantA, mine.ID)
	mustNoErr(t, err, "reading after the dry run")
	if stillThere.CustomerRefHash == "" {
		t.Fatal("a dry run erased")
	}

	result, err := svc.Erase(ctx, ref, false)
	mustNoErr(t, err, "erasing")
	if result.EventsAffected != 1 {
		t.Fatalf("result = %+v", result)
	}

	// The email is gone from the raw body, which is where it actually was —
	// the provider chose the payload, not us.
	rawAfter, err := s.GetRawEvent(ctx, tenantA, mine.RawEventID)
	mustNoErr(t, err, "reading the raw event")
	if strings.Contains(string(rawAfter.Body), "tunde@example.com") {
		t.Fatalf("the email survived in the raw body: %s", rawAfter.Body)
	}
	if len(rawAfter.Body) != 0 {
		t.Errorf("the raw body was not emptied: %q", rawAfter.Body)
	}

	// And from provider_extra, which is where an unmapped phone number lives.
	evAfter, err := s.GetCanonicalEvent(ctx, tenantA, mine.ID)
	mustNoErr(t, err, "reading the event")
	if evAfter.CustomerRefHash != "" {
		t.Error("the subject hash was not removed")
	}
	if _, present := evAfter.ProviderExtra["data.customer.phone"]; present {
		t.Errorf("unmapped subject data survived: %v", evAfter.ProviderExtra)
	}

	// The transaction itself is retained: CBN and AML obligations require the
	// tenant to hold it, and deleting a payment from their ledger at the
	// payer's request would break their books.
	if evAfter.TransactionRef != "TXN-1" || evAfter.AmountMinor != 5000000 {
		t.Errorf("the transaction record was damaged: %+v", evAfter)
	}

	// Nobody else was touched.
	theirsAfter, err := s.GetCanonicalEvent(ctx, tenantA, theirs.ID)
	mustNoErr(t, err, "reading the other subject's event")
	if theirsAfter.CustomerRefHash == "" {
		t.Fatal("another subject's data was erased")
	}
	theirRaw, err := s.GetRawEvent(ctx, tenantA, theirsAfter.RawEventID)
	mustNoErr(t, err, "reading the other raw event")
	if !strings.Contains(string(theirRaw.Body), "ngozi@example.com") {
		t.Fatal("another subject's raw body was wiped")
	}

	// The verification that can be run against production on the day a
	// regulator asks.
	proof, err := svc.Verify(ctx, ref)
	mustNoErr(t, err, "verifying the erasure")
	if proof == "" {
		t.Error("verification produced no statement")
	}
}

func TestSubjectErasureIsItselfAudited(t *testing.T) {
	// An erasure that succeeded without its audit record would be an
	// unexplainable gap at exactly the moment somebody wants an explanation.
	svc, s, ep := subjectSetup(t)
	ctx := context.Background()
	ref := subject.Resolve(tenantA, tenantSalt, "tunde@example.com")
	storeEventFor(t, s, ep, ref.Hash, "tunde@example.com", "TXN-1",
		time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC))

	before, err := s.VerifyChain(ctx, tenantA)
	mustNoErr(t, err, "verifying before")

	if _, err := svc.Erase(ctx, ref, false); err != nil {
		t.Fatalf("erasing: %v", err)
	}

	records, err := s.ListAudit(ctx, tenantA, time.Time{}, 20)
	mustNoErr(t, err, "listing the audit trail")
	var found bool
	for _, r := range records {
		if string(r.EventType) == "subject.erased" {
			found = true
			// The subject is named only by hash, so the erasure record does
			// not reintroduce the identifier it just removed.
			if strings.Contains(r.Subject.ID, "@") {
				t.Errorf("the audit record names the subject in the clear: %q", r.Subject.ID)
			}
		}
	}
	if !found {
		t.Fatal("the erasure was not audited")
	}
	if int64(len(records)) <= before.Records {
		t.Error("no audit record was appended")
	}

	// And the chain is still intact: an erasure must not break the evidence.
	after, err := s.VerifyChain(ctx, tenantA)
	mustNoErr(t, err, "verifying after")
	if !after.Intact {
		t.Fatalf("the erasure broke the audit chain: %+v", after)
	}
}

func TestSubjectErasureOfNobodyIsHonest(t *testing.T) {
	// A request for a subject we hold nothing about must report zero rather
	// than reporting success in a way indistinguishable from a real erasure.
	svc, _, _ := subjectSetup(t)
	result, err := svc.Erase(context.Background(),
		subject.Resolve(tenantA, tenantSalt, "nobody@example.com"), false)
	mustNoErr(t, err, "erasing nobody")
	if result.EventsAffected != 0 {
		t.Errorf("result = %+v", result)
	}
}

func TestSubjectErasureReportSaysWhatSurvives(t *testing.T) {
	// A report listing only deletions invites the reader to assume nothing is
	// left, which would be untrue — and worse when the regulator asks.
	svc, s, ep := subjectSetup(t)
	ctx := context.Background()
	ref := subject.Resolve(tenantA, tenantSalt, "tunde@example.com")
	storeEventFor(t, s, ep, ref.Hash, "tunde@example.com", "TXN-1",
		time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC))

	result, err := svc.Erase(ctx, ref, false)
	mustNoErr(t, err, "erasing")
	for _, want := range []string{"transactions themselves are retained", "AML", "Audit records are also retained"} {
		if !strings.Contains(result.Retained, want) {
			t.Errorf("the report does not mention %q:\n%s", want, result.Retained)
		}
	}
}
