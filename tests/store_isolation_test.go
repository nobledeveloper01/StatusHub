package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

// TestStoreTenantIsolation is a blocking CI gate (§8.1).
//
// It writes every kind of tenant-owned row as tenant A and then asks for each
// one as tenant B. Every read must come back ErrNotFound — the same error a
// row that does not exist produces. A distinct "forbidden" would confirm the
// row is real, which is a working cross-tenant enumeration oracle: an
// attacker with one valid key could map another fintech's event IDs one
// request at a time.
func TestStoreTenantIsolation(t *testing.T) {
	ctx := context.Background()
	s := memStore(t)

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "creating A's endpoint")

	dst := domain.Destination{
		ID: domain.NewID(domain.PrefixDestination), TenantID: tenantA,
		URL: "https://acme.example.com/hooks", SigningSecretRef: "static://sign",
		RetryPolicy: domain.DefaultRetryPolicy(), Enabled: true,
	}
	mustNoErr(t, s.CreateDestination(ctx, dst), "creating A's destination")

	raw := domain.RawEvent{
		ID: domain.NewID(domain.PrefixRawEvent), TenantID: tenantA, EndpointID: ep.ID,
		Provider: "paystack", Body: []byte(`{"data":{"reference":"TXN-1"}}`),
		BodySHA256: "abc", SignatureValid: true, ReceivedAt: time.Now().UTC(),
	}
	mustNoErr(t, s.PutRawEvent(ctx, raw), "storing A's raw event")

	ev := domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, RawEventID: raw.ID,
		Provider: "paystack", ProviderEventID: "evt_1", EventType: domain.EventPaymentCompleted,
		TransactionRef: "TXN-1", Status: domain.StatusSuccess, AmountMinor: 5000000,
		Currency: "NGN", OccurredAt: time.Now().UTC(), MappingComplete: true,
	}
	mustNoErr(t, s.PutCanonicalEvent(ctx, ev), "storing A's canonical event")

	deliveryID, err := s.EnqueueDelivery(ctx, domain.Delivery{
		TenantID: tenantA, EventID: ev.ID, DestinationID: dst.ID,
		Shard:    domain.ShardFor(ev.TransactionRef, domain.DefaultShards),
		Sequence: 1, Status: domain.DeliveryPending,
	})
	mustNoErr(t, err, "enqueuing A's delivery")

	mustNoErr(t, s.AppendAudit(ctx, domain.AuditRecord{
		TenantID: tenantA, EventType: domain.AuditEventReceived,
		Actor: domain.Actor{Type: domain.ActorSystem}, Subject: domain.Subject{Type: "raw_event", ID: raw.ID},
	}), "appending A's audit record")

	// Every single-row read, as the wrong tenant.
	reads := map[string]func() error{
		"endpoint": func() error {
			_, err := s.GetEndpoint(ctx, tenantB, ep.ID)
			return err
		},
		"destination": func() error {
			_, err := s.GetDestination(ctx, tenantB, dst.ID)
			return err
		},
		"raw event": func() error {
			_, err := s.GetRawEvent(ctx, tenantB, raw.ID)
			return err
		},
		"canonical event": func() error {
			_, err := s.GetCanonicalEvent(ctx, tenantB, ev.ID)
			return err
		},
		"canonical event by dedupe key": func() error {
			_, err := s.GetCanonicalEventByDedupeKey(ctx, tenantB, "paystack", "evt_1")
			return err
		},
		"delivery": func() error {
			_, err := s.GetDelivery(ctx, tenantB, deliveryID)
			return err
		},
	}
	for name, read := range reads {
		t.Run(name, func(t *testing.T) {
			err := read()
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("tenant B read A's %s and got %v; must be ErrNotFound, never a distinguishable refusal", name, err)
			}
		})
	}

	// Every list, as the wrong tenant. These must be empty rather than
	// filtered-with-a-hint.
	t.Run("lists are empty", func(t *testing.T) {
		if eps, err := s.ListEndpoints(ctx, tenantB); err != nil || len(eps) != 0 {
			t.Errorf("endpoints: %d rows, %v", len(eps), err)
		}
		if ds, err := s.ListDestinations(ctx, tenantB); err != nil || len(ds) != 0 {
			t.Errorf("destinations: %d rows, %v", len(ds), err)
		}
		if evs, err := s.QueryEvents(ctx, tenantB, store.EventQuery{}); err != nil || len(evs) != 0 {
			t.Errorf("events: %d rows, %v", len(evs), err)
		}
		if dl, err := s.QueryDeliveries(ctx, tenantB, store.DeliveryQuery{}); err != nil || len(dl) != 0 {
			t.Errorf("deliveries: %d rows, %v", len(dl), err)
		}
		if fs, err := s.ListSignatureFailures(ctx, tenantB, "", time.Time{}, 10); err != nil || len(fs) != 0 {
			t.Errorf("signature failures: %d rows, %v", len(fs), err)
		}
		if ds, err := s.ListDeliveriesForEvent(ctx, tenantB, ev.ID); err != nil || len(ds) != 0 {
			t.Errorf("deliveries for event: %d rows, %v", len(ds), err)
		}
		if au, err := s.ListAudit(ctx, tenantB, time.Time{}, 10); err != nil || len(au) != 0 {
			t.Errorf("audit: %d rows, %v", len(au), err)
		}
	})

	// Writes scoped to the wrong tenant must not land either.
	t.Run("writes are refused", func(t *testing.T) {
		if err := s.UpdateEndpoint(ctx, tenantB, ep); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("tenant B updated A's endpoint: %v", err)
		}
		if err := s.DeleteEndpoint(ctx, tenantB, ep.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("tenant B deleted A's endpoint: %v", err)
		}
		if err := s.UpdateDestination(ctx, tenantB, dst); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("tenant B updated A's destination: %v", err)
		}
		if err := s.MarkNormalisationFailure(ctx, tenantB, raw.ID, "nope"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("tenant B marked A's raw event failed: %v", err)
		}
		// And A's rows survived the attempts.
		if _, err := s.GetEndpoint(ctx, tenantA, ep.ID); err != nil {
			t.Errorf("A's endpoint was damaged: %v", err)
		}
	})

	t.Run("audit chains do not interleave", func(t *testing.T) {
		// Each tenant's chain is independent, so one tenant's activity can
		// never be inferred from gaps or hash values in another's.
		mustNoErr(t, s.AppendAudit(ctx, domain.AuditRecord{
			TenantID: tenantB, EventType: domain.AuditEventReceived,
			Actor: domain.Actor{Type: domain.ActorSystem}, Subject: domain.Subject{Type: "raw_event", ID: "sh_raw_b"},
		}), "appending B's audit record")

		proofA, err := s.VerifyChain(ctx, tenantA)
		mustNoErr(t, err, "verifying A's chain")
		proofB, err := s.VerifyChain(ctx, tenantB)
		mustNoErr(t, err, "verifying B's chain")

		if !proofA.Intact || !proofB.Intact {
			t.Fatalf("chains not intact: A=%+v B=%+v", proofA, proofB)
		}
		if proofA.Records != 1 || proofB.Records != 1 {
			t.Errorf("chains interleaved: A has %d records, B has %d", proofA.Records, proofB.Records)
		}
		if proofA.Head == proofB.Head {
			t.Error("two tenants' chains produced the same head hash")
		}
	})
}

func TestStoreDeduplicatesProviderRedeliveries(t *testing.T) {
	ctx := context.Background()
	s := memStore(t)

	ev := domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "flutterwave",
		ProviderEventID: "4589301", EventType: domain.EventPaymentCompleted,
		TransactionRef: "TXN-1", Status: domain.StatusSuccess, OccurredAt: time.Now().UTC(),
	}
	mustNoErr(t, s.PutCanonicalEvent(ctx, ev), "first write")

	// The provider redelivers. A second canonical event would mean the
	// customer's ledger sees the same payment twice.
	second := ev
	second.ID = domain.NewID(domain.PrefixEvent)
	if err := s.PutCanonicalEvent(ctx, second); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("a redelivery created a second event: %v", err)
	}

	// The same provider event ID under a different tenant is a different
	// event, and must not collide.
	other := ev
	other.ID = domain.NewID(domain.PrefixEvent)
	other.TenantID = tenantB
	mustNoErr(t, s.PutCanonicalEvent(ctx, other), "the same provider ID for another tenant")
}
