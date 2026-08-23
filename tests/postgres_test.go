package tests

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/migrate"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

// pgStore returns a migrated Postgres store, or skips.
//
// Skipping rather than failing when no database is configured is deliberate:
// `go test ./tests/...` has to work on a laptop with nothing installed, or
// people stop running it. CI always sets the variable, so the integration
// path is never skipped where it matters.
func pgStore(t *testing.T) *store.Postgres {
	t.Helper()
	dsn := os.Getenv("STATUSHUB_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("STATUSHUB_TEST_DATABASE_URL is not set; skipping the Postgres integration tests")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	mustNoErr(t, err, "connecting")
	t.Cleanup(pool.Close)

	// A clean schema per run. Reusing one across runs makes a failure depend
	// on which test ran last, which is the hardest kind of flake to chase.
	_, err = pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)
	mustNoErr(t, err, "resetting the schema")

	ran, err := migrate.Up(ctx, pool)
	mustNoErr(t, err, "migrating")
	if len(ran) == 0 {
		t.Fatal("no migrations ran against a freshly dropped schema")
	}

	s := store.NewPostgresFromPool(pool)
	for _, tn := range []domain.Tenant{
		{ID: tenantA, Slug: slugA, Name: "Acme Payments"},
		{ID: tenantB, Slug: slugB, Name: "Globex Financial"},
	} {
		mustNoErr(t, s.CreateTenant(ctx, tn), "creating "+tn.ID)
	}
	return s
}

func TestPostgresStoreRoundTrip(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack",
		AllowedSourceCIDRs: []string{"196.6.103.0/24"}, Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "creating the endpoint")

	got, err := s.GetEndpoint(ctx, tenantA, ep.ID)
	mustNoErr(t, err, "reading it back")
	if got.ReceiverToken != ep.ReceiverToken || got.AdapterName != "paystack" {
		t.Errorf("endpoint round-tripped as %+v", got)
	}
	if len(got.AllowedSourceCIDRs) != 1 {
		t.Errorf("allowed CIDRs = %v", got.AllowedSourceCIDRs)
	}

	// The receiver's hot lookup, with every URL component checked.
	resolved, tenant, err := s.ResolveReceiver(ctx, slugA, "paystack", "live", ep.ReceiverToken)
	mustNoErr(t, err, "resolving the receiver URL")
	if resolved.ID != ep.ID || tenant.Slug != slugA {
		t.Errorf("resolved to %s / %s", resolved.ID, tenant.Slug)
	}
	// A token valid for one endpoint must not resolve against another
	// provider or environment.
	if _, _, err := s.ResolveReceiver(ctx, slugA, "stripe", "live", ep.ReceiverToken); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a token resolved against the wrong provider: %v", err)
	}
	if _, _, err := s.ResolveReceiver(ctx, slugA, "paystack", "test", ep.ReceiverToken); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a live token resolved against the test environment: %v", err)
	}
}

func TestPostgresTenantIsolation(t *testing.T) {
	// The blocking CI gate, against the real database this time — because
	// row-level security and a WHERE clause can disagree, and the whole point
	// of having both is that one of them is written by a person.
	s := pgStore(t)
	ctx := context.Background()

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "endpoint")

	dst := domain.Destination{
		ID: domain.NewID(domain.PrefixDestination), TenantID: tenantA,
		URL: "https://acme.example.com/hooks", SigningSecretRef: signingRef,
		RetryPolicy: domain.DefaultRetryPolicy(), Enabled: true,
	}
	mustNoErr(t, s.CreateDestination(ctx, dst), "destination")

	raw := domain.RawEvent{
		ID: domain.NewID(domain.PrefixRawEvent), TenantID: tenantA, EndpointID: ep.ID,
		Provider: "paystack", Body: []byte(`{"data":{"reference":"TXN-PG"}}`),
		BodySHA256: "hash", SignatureValid: true, ReceivedAt: time.Now().UTC(),
		Headers: map[string]string{"user-agent": "Paystack/1.0"},
		// A real source address. Without one, the inet column is never
		// exercised — which is exactly how a scan bug reached a running
		// server: every stored event had a nil address and the column was
		// only ever read as NULL.
		SourceIP: netip.MustParseAddr("102.89.34.7"),
	}
	mustNoErr(t, s.PutRawEvent(ctx, raw), "raw event")

	ev := domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, RawEventID: raw.ID,
		Provider: "paystack", ProviderEventID: "evt-pg-1", EventType: domain.EventPaymentCompleted,
		TransactionRef: "TXN-PG", Status: domain.StatusSuccess, AmountMinor: 5000000,
		Currency: "NGN", OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(),
		ProviderExtra: map[string]any{"channel": "card"}, MappingComplete: true,
	}
	mustNoErr(t, s.PutCanonicalEvent(ctx, ev), "canonical event")

	deliveryID, err := s.EnqueueDelivery(ctx, domain.Delivery{
		TenantID: tenantA, EventID: ev.ID, DestinationID: dst.ID,
		TransactionRef: "TXN-PG", Shard: domain.ShardFor("TXN-PG", domain.DefaultShards),
		Sequence: 1, Status: domain.DeliveryPending,
	})
	mustNoErr(t, err, "delivery")

	for name, read := range map[string]func() error{
		"endpoint":    func() error { _, e := s.GetEndpoint(ctx, tenantB, ep.ID); return e },
		"destination": func() error { _, e := s.GetDestination(ctx, tenantB, dst.ID); return e },
		"raw event":   func() error { _, e := s.GetRawEvent(ctx, tenantB, raw.ID); return e },
		"event":       func() error { _, e := s.GetCanonicalEvent(ctx, tenantB, ev.ID); return e },
		"delivery":    func() error { _, e := s.GetDelivery(ctx, tenantB, deliveryID); return e },
	} {
		t.Run(name, func(t *testing.T) {
			if err := read(); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("tenant B read A's %s and got %v; must be ErrNotFound", name, err)
			}
		})
	}
}

// TestPostgresReadsBackASourceAddress covers the column that a scan bug
// reached a running server through: every test event had a nil address, so
// the inet path was never read and pgx's refusal to scan it went unnoticed
// until a real webhook arrived.
func TestPostgresReadsBackASourceAddress(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "endpoint")

	for _, addr := range []string{"102.89.34.7", "2606:4700:4700::1111"} {
		raw := domain.RawEvent{
			ID: domain.NewID(domain.PrefixRawEvent), TenantID: tenantA, EndpointID: ep.ID,
			Provider: "paystack", Body: []byte(`{"data":{"reference":"TXN-IP"}}`),
			BodySHA256: "h", SignatureValid: false, SignatureError: "forged",
			SourceIP: netip.MustParseAddr(addr), ReceivedAt: time.Now().UTC(),
		}
		mustNoErr(t, s.PutRawEvent(ctx, raw), "storing an event from "+addr)

		got, err := s.GetRawEvent(ctx, tenantA, raw.ID)
		mustNoErr(t, err, "reading it back")
		if got.SourceIP.String() != addr {
			t.Errorf("source address round-tripped as %q, want %q", got.SourceIP, addr)
		}
	}

	// And through the two paths that actually read it in production: the
	// normaliser's work queue and the signature-failure view.
	if _, err := s.ListUnnormalised(ctx, 10); err != nil {
		t.Errorf("listing pending work with a stored source address: %v", err)
	}
	failures, err := s.ListSignatureFailures(ctx, tenantA, ep.ID, time.Time{}, 10)
	mustNoErr(t, err, "listing signature failures")
	if len(failures) != 2 {
		t.Fatalf("%d failures listed, want 2", len(failures))
	}
	if !failures[0].SourceIP.IsValid() {
		t.Error("the signature-failure view lost the source address, which is the first thing an operator looks at")
	}
}

func TestPostgresDeduplicatesAtTheDatabase(t *testing.T) {
	// The unique index, not a check-then-insert. Two receiver replicas
	// processing a provider's retry at the same moment would both pass an
	// application check and both write.
	s := pgStore(t)
	ctx := context.Background()

	ev := domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "flutterwave",
		ProviderEventID: "4589301", EventType: domain.EventPaymentCompleted,
		TransactionRef: "TXN-DUP", Status: domain.StatusSuccess,
		OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(),
	}
	mustNoErr(t, s.PutCanonicalEvent(ctx, ev), "first write")

	second := ev
	second.ID = domain.NewID(domain.PrefixEvent)
	if err := s.PutCanonicalEvent(ctx, second); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("a redelivery created a second event: %v", err)
	}

	// Two events from a provider that supplies no event ID must both be
	// stored: the unique index is partial for exactly this reason.
	for i := 0; i < 2; i++ {
		noID := domain.CanonicalEvent{
			ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "paystack",
			EventType: domain.EventPaymentCompleted, TransactionRef: "TXN-NOID",
			Status: domain.StatusSuccess, OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(),
		}
		mustNoErr(t, s.PutCanonicalEvent(ctx, noID), "storing an event with no provider ID")
	}
}

func TestPostgresClaimEnforcesOrdering(t *testing.T) {
	// The claim query is the single most important one in the dispatcher.
	// Two events about one transaction must never be claimable together.
	s := pgStore(t)
	ctx := context.Background()

	dst := domain.Destination{
		ID: domain.NewID(domain.PrefixDestination), TenantID: tenantA,
		URL: "https://acme.example.com/hooks", SigningSecretRef: signingRef,
		RetryPolicy: domain.DefaultRetryPolicy(), Enabled: true,
	}
	mustNoErr(t, s.CreateDestination(ctx, dst), "destination")

	shard := domain.ShardFor("TXN-ORDER-PG", domain.DefaultShards)
	var ids []int64
	for i := 0; i < 3; i++ {
		ev := domain.CanonicalEvent{
			ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "paystack",
			EventType: domain.EventPaymentPending, TransactionRef: "TXN-ORDER-PG",
			Status: domain.StatusPending, OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(),
		}
		mustNoErr(t, s.PutCanonicalEvent(ctx, ev), "event")
		seq, err := s.NextSequence(ctx, tenantA, "TXN-ORDER-PG")
		mustNoErr(t, err, "sequence")
		if seq != int64(i+1) {
			t.Fatalf("sequence = %d, want %d", seq, i+1)
		}
		id, err := s.EnqueueDelivery(ctx, domain.Delivery{
			TenantID: tenantA, EventID: ev.ID, DestinationID: dst.ID,
			TransactionRef: "TXN-ORDER-PG", Shard: shard, Sequence: seq,
			Status: domain.DeliveryPending,
		})
		mustNoErr(t, err, "enqueue")
		ids = append(ids, id)
	}

	now := time.Now().UTC()
	claimed, err := s.ClaimDue(ctx, shard, now, 32, time.Minute)
	mustNoErr(t, err, "claiming")
	if len(claimed) != 1 {
		t.Fatalf("%d deliveries claimed for one transaction reference; ordering requires exactly 1", len(claimed))
	}
	if claimed[0].ID != ids[0] {
		t.Fatalf("claimed delivery %d, want the first one (%d)", claimed[0].ID, ids[0])
	}
	if claimed[0].Attempt != 1 {
		t.Errorf("attempt = %d, want 1 after claiming", claimed[0].Attempt)
	}

	// While the first is in flight, nothing else for that reference is
	// claimable — including from another replica, which is what the lease
	// check in the query is for.
	again, err := s.ClaimDue(ctx, shard, now, 32, time.Minute)
	mustNoErr(t, err, "claiming again")
	if len(again) != 0 {
		t.Fatalf("%d deliveries claimed while one was in flight for the same reference", len(again))
	}

	// Completing it releases the key.
	done := claimed[0]
	done.Status = domain.DeliverySucceeded
	mustNoErr(t, s.CompleteDelivery(ctx, done), "completing")

	next, err := s.ClaimDue(ctx, shard, now, 32, time.Minute)
	mustNoErr(t, err, "claiming the next")
	if len(next) != 1 || next[0].ID != ids[1] {
		t.Fatalf("after completion, claimed %+v; want the second delivery", next)
	}
}

func TestPostgresExpiredLeasesAreReclaimed(t *testing.T) {
	// A dispatcher killed mid-delivery holds its lease. Without reclaim the
	// delivery stays in_flight forever and — because in-flight blocks the
	// reference — that transaction stalls permanently.
	s := pgStore(t)
	ctx := context.Background()

	dst := domain.Destination{
		ID: domain.NewID(domain.PrefixDestination), TenantID: tenantA,
		URL: "https://acme.example.com/hooks", SigningSecretRef: signingRef,
		RetryPolicy: domain.DefaultRetryPolicy(), Enabled: true,
	}
	mustNoErr(t, s.CreateDestination(ctx, dst), "destination")

	ev := domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "paystack",
		EventType: domain.EventPaymentCompleted, TransactionRef: "TXN-LEASE",
		Status: domain.StatusSuccess, OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(),
	}
	mustNoErr(t, s.PutCanonicalEvent(ctx, ev), "event")
	shard := domain.ShardFor("TXN-LEASE", domain.DefaultShards)
	_, err := s.EnqueueDelivery(ctx, domain.Delivery{
		TenantID: tenantA, EventID: ev.ID, DestinationID: dst.ID,
		TransactionRef: "TXN-LEASE", Shard: shard, Sequence: 1, Status: domain.DeliveryPending,
	})
	mustNoErr(t, err, "enqueue")

	now := time.Now().UTC()
	claimed, err := s.ClaimDue(ctx, shard, now, 10, time.Second)
	mustNoErr(t, err, "claiming")
	if len(claimed) != 1 {
		t.Fatalf("%d claimed", len(claimed))
	}

	// The dispatcher "dies" here: nothing completes the delivery.
	later := now.Add(2 * time.Second)
	n, err := s.ReclaimExpiredLeases(ctx, later)
	mustNoErr(t, err, "reclaiming")
	if n != 1 {
		t.Fatalf("reclaimed %d leases, want 1", n)
	}

	recovered, err := s.ClaimDue(ctx, shard, later, 10, time.Minute)
	mustNoErr(t, err, "claiming after reclaim")
	if len(recovered) != 1 {
		t.Fatalf("the abandoned delivery was not picked up: %d claimed", len(recovered))
	}
}

func TestPostgresAuditChainIsGaplessAndVerifies(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		mustNoErr(t, s.AppendAudit(ctx, domain.AuditRecord{
			TenantID: tenantA, EventType: domain.AuditEventReceived,
			Actor: domain.Actor{Type: domain.ActorSystem}, Subject: domain.Subject{Type: "x", ID: "1"},
			Payload: map[string]any{"n": i},
		}), "appending")
	}

	proof, err := s.VerifyChain(ctx, tenantA)
	mustNoErr(t, err, "verifying")
	if !proof.Intact || proof.Records != 10 {
		t.Fatalf("proof = %+v", proof)
	}

	// The trigger refuses updates and deletes regardless of role — including
	// for a superuser, whose mistakes are the ones nothing else catches.
	pool := s.Pool()
	if _, err := pool.Exec(ctx, `UPDATE audit_records SET payload = '{}' WHERE tenant_id = $1`, tenantA); err == nil {
		t.Fatal("an audit record was updated; the append-only trigger did not fire")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_records WHERE tenant_id = $1`, tenantA); err == nil {
		t.Fatal("an audit record was deleted; the append-only trigger did not fire")
	}

	// And the chain still verifies after the failed attempts.
	proof, err = s.VerifyChain(ctx, tenantA)
	mustNoErr(t, err, "re-verifying")
	if !proof.Intact || proof.Records != 10 {
		t.Fatalf("proof after tamper attempts = %+v", proof)
	}
}

func TestPostgresNormalisationFailureKeepsTheRawEvent(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "endpoint")

	body := []byte(`{"event":"charge.success","data":{}}`)
	raw := domain.RawEvent{
		ID: domain.NewID(domain.PrefixRawEvent), TenantID: tenantA, EndpointID: ep.ID,
		Provider: "paystack", Body: body, BodySHA256: "hash",
		SignatureValid: true, ReceivedAt: time.Now().UTC(),
	}
	mustNoErr(t, s.PutRawEvent(ctx, raw), "raw event")

	pending, err := s.ListUnnormalised(ctx, 10)
	mustNoErr(t, err, "listing pending")
	if len(pending) != 1 {
		t.Fatalf("%d pending, want 1", len(pending))
	}

	mustNoErr(t, s.MarkNormalisationFailure(ctx, tenantA, raw.ID, "no transaction reference"), "marking failed")

	// It stops being handed out as work.
	pending, err = s.ListUnnormalised(ctx, 10)
	mustNoErr(t, err, "listing pending again")
	if len(pending) != 0 {
		t.Fatalf("a failed event is still queued as pending work")
	}
	// And the bytes are untouched, which is the entire recovery path.
	stored, err := s.GetRawEvent(ctx, tenantA, raw.ID)
	mustNoErr(t, err, "reading the raw event")
	if string(stored.Body) != string(body) {
		t.Fatal("the raw bytes were altered by a failed normalisation")
	}
}

func TestPostgresUnknownStatusesAggregate(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		mustNoErr(t, s.PutCanonicalEvent(ctx, domain.CanonicalEvent{
			ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "paystack",
			EventType: domain.EventUnknown, TransactionRef: "TXN-U", Status: domain.StatusUnknown,
			UnmappedStatus: "part_settled", OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(),
		}), "storing")
	}
	mustNoErr(t, s.PutCanonicalEvent(ctx, domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "stripe",
		EventType: domain.EventUnknown, TransactionRef: "TXN-V", Status: domain.StatusUnknown,
		UnmappedStatus: "requires_settlement", OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(),
	}), "storing")

	unknown, err := s.UnknownStatuses(ctx, tenantA, time.Now().Add(-time.Hour))
	mustNoErr(t, err, "aggregating")
	if len(unknown) != 2 {
		t.Fatalf("%d distinct unmapped values, want 2", len(unknown))
	}
	// Most frequent first: that is the adapter fix worth doing next.
	if unknown[0].RawValue != "part_settled" || unknown[0].Count != 3 {
		t.Errorf("first = %+v", unknown[0])
	}
	if unknown[0].SampleEvent == "" {
		t.Error("no sample event, so an engineer cannot see the payload")
	}
}
