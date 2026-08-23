package tests

import (
	"bytes"
	"context"
	"encoding/csv"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/migrate"
	"github.com/nobledeveloper01/StatusHub/internal/store"
	"github.com/nobledeveloper01/StatusHub/internal/usage"
)

func usageSetup(t *testing.T) (*usage.Meter, *store.Postgres, domain.Endpoint) {
	t.Helper()
	dsn := os.Getenv("STATUSHUB_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("STATUSHUB_TEST_DATABASE_URL is not set; skipping the usage tests")
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
	for _, tn := range []domain.Tenant{
		{ID: tenantA, Slug: slugA, Name: "Acme"},
		{ID: tenantB, Slug: slugB, Name: "Globex"},
	} {
		mustNoErr(t, s.CreateTenant(ctx, tn), "tenant")
	}

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "endpoint")

	return usage.New(pool, func() time.Time { return time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) }), s, ep
}

func storeRawEvent(t *testing.T, s *store.Postgres, ep domain.Endpoint, provider string, at time.Time, valid bool) domain.RawEvent {
	t.Helper()
	raw := domain.RawEvent{
		ID: domain.NewID(domain.PrefixRawEvent), TenantID: ep.TenantID, EndpointID: ep.ID,
		Provider: provider, Body: []byte(`{"reference":"TXN"}`), BodySHA256: "h",
		SignatureValid: valid, ReceivedAt: at,
	}
	mustNoErr(t, s.PutRawEvent(context.Background(), raw), "storing")
	return raw
}

func TestUsageCountsWhatTheCustomerCanSee(t *testing.T) {
	// The billing metric is chosen precisely so the customer can reconcile
	// it. That only holds if it is derived from the rows the event explorer
	// shows — a separate counter drifts, and a bill that disagrees with the
	// customer's own view of the same data is worse than no auditable metric.
	m, s, ep := usageSetup(t)
	ctx := context.Background()

	day1 := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 8, 12, 9, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		storeRawEvent(t, s, ep, "paystack", day1, true)
	}
	storeRawEvent(t, s, ep, "paystack", day1, false) // a forgery
	for i := 0; i < 3; i++ {
		storeRawEvent(t, s, ep, "paystack", day2, true)
	}

	r, err := m.Usage(ctx, tenantA, day1.Truncate(24*time.Hour), day2.Add(24*time.Hour))
	mustNoErr(t, err, "metering")

	if r.Total.Received != 9 {
		t.Fatalf("received = %d, want 9", r.Total.Received)
	}
	// Forgeries are billed and broken out: the work of receiving, verifying
	// and storing happened, and the customer's provider dashboard counts
	// deliveries attempted too.
	if r.Total.Rejected != 1 {
		t.Errorf("signature failures = %d, want 1", r.Total.Rejected)
	}
	if len(r.Days) != 2 {
		t.Fatalf("%d days reported, want 2", len(r.Days))
	}
	if r.Days[0].Date != "2026-08-11" || r.Days[0].Received != 6 {
		t.Errorf("day 1 = %+v", r.Days[0])
	}

	// Every event billed must be one the customer can find.
	events, err := s.ListUnnormalised(ctx, 100)
	mustNoErr(t, err, "listing")
	if int64(len(events)) != r.Total.Received-r.Total.Rejected {
		t.Errorf("%d events are visible but %d billable were counted",
			len(events), r.Total.Received-r.Total.Rejected)
	}
}

func TestUsageIsPerTenant(t *testing.T) {
	m, s, ep := usageSetup(t)
	ctx := context.Background()
	at := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)

	epB := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantB, Provider: "stripe",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "stripe", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, epB), "B's endpoint")

	storeRawEvent(t, s, ep, "paystack", at, true)
	for i := 0; i < 4; i++ {
		storeRawEvent(t, s, epB, "stripe", at, true)
	}

	r, err := m.Usage(ctx, tenantA, at.Add(-time.Hour), at.Add(time.Hour))
	mustNoErr(t, err, "metering A")
	if r.Total.Received != 1 {
		t.Fatalf("tenant A was billed for %d events; tenant B's must not be included", r.Total.Received)
	}
}

func TestUsageRangeIsHalfOpen(t *testing.T) {
	// A closed range either double-counts the boundary between consecutive
	// months or misses it, and both surface as an unexplainable one-event
	// discrepancy on exactly the invoice somebody is querying.
	m, s, ep := usageSetup(t)
	ctx := context.Background()

	boundary := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	storeRawEvent(t, s, ep, "paystack", boundary.Add(-time.Second), true) // August
	storeRawEvent(t, s, ep, "paystack", boundary, true)                   // September

	august, err := m.Usage(ctx, tenantA, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), boundary)
	mustNoErr(t, err, "metering August")
	september, err := m.Usage(ctx, tenantA, boundary, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	mustNoErr(t, err, "metering September")

	if august.Total.Received != 1 {
		t.Errorf("August = %d, want 1", august.Total.Received)
	}
	if september.Total.Received != 1 {
		t.Errorf("September = %d, want 1", september.Total.Received)
	}
	if august.Total.Received+september.Total.Received != 2 {
		t.Error("consecutive periods do not sum to the total; the boundary is counted twice or not at all")
	}
}

func TestUsageDoesNotMultiplyByDestinationCount(t *testing.T) {
	// A fanned-out event is one event received and several delivered.
	// Joining deliveries into the receive query would bill the customer once
	// per destination.
	m, s, ep := usageSetup(t)
	ctx := context.Background()
	at := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)

	for i := 0; i < 2; i++ {
		mustNoErr(t, s.CreateDestination(ctx, domain.Destination{
			ID: domain.NewID(domain.PrefixDestination), TenantID: tenantA,
			URL: "https://acme.example.com/hooks", SigningSecretRef: signingRef,
			RetryPolicy: domain.DefaultRetryPolicy(), Enabled: true,
		}), "destination")
	}

	raw := storeRawEvent(t, s, ep, "paystack", at, true)
	ev := domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, RawEventID: raw.ID,
		Provider: "paystack", EventType: domain.EventPaymentCompleted, TransactionRef: "TXN",
		Status: domain.StatusSuccess, OccurredAt: at, ReceivedAt: at,
	}
	mustNoErr(t, s.PutCanonicalEvent(ctx, ev), "event")

	dests, err := s.ListDestinations(ctx, tenantA)
	mustNoErr(t, err, "listing destinations")
	for _, d := range dests {
		id, err := s.EnqueueDelivery(ctx, domain.Delivery{
			TenantID: tenantA, EventID: ev.ID, DestinationID: d.ID, TransactionRef: "TXN",
			Shard: 1, Sequence: 1, Status: domain.DeliveryPending, CreatedAt: at,
		})
		mustNoErr(t, err, "enqueue")
		del, err := s.GetDelivery(ctx, tenantA, id)
		mustNoErr(t, err, "get")
		del.Status = domain.DeliverySucceeded
		mustNoErr(t, s.CompleteDelivery(ctx, del), "complete")
	}

	r, err := m.Usage(ctx, tenantA, at.Add(-time.Hour), at.Add(time.Hour))
	mustNoErr(t, err, "metering")
	if r.Total.Received != 1 {
		t.Fatalf("received = %d; one event fanned to two destinations is still one event received", r.Total.Received)
	}
	if r.Total.Delivered != 2 {
		t.Errorf("delivered = %d, want 2", r.Total.Delivered)
	}
}

func TestUsageCSVIsSafeToOpenInASpreadsheet(t *testing.T) {
	// A declarative adapter's name is customer-supplied, and a CSV that
	// executes a formula on open is a real finding in a real penetration
	// test.
	r := usage.Report{
		From: "2026-08-01T00:00:00Z", To: "2026-09-01T00:00:00Z",
		Days: []usage.Day{
			{Date: "2026-08-11", Provider: "=cmd|'/c calc'!A1", Received: 3},
			{Date: "2026-08-12", Provider: "paystack", Received: 5},
		},
		Total: usage.Day{Date: "total", Provider: "all", Received: 8},
	}
	var buf bytes.Buffer
	mustNoErr(t, r.WriteCSV(&buf), "writing CSV")

	records, err := csv.NewReader(&buf).ReadAll()
	mustNoErr(t, err, "reading it back")
	if len(records) != 4 {
		t.Fatalf("%d rows, want a header, two days and a total", len(records))
	}
	if !strings.HasPrefix(records[1][1], "'") {
		t.Fatalf("a formula-shaped provider name was not defused: %q", records[1][1])
	}
	if records[2][1] != "paystack" {
		t.Errorf("an ordinary value was mangled: %q", records[2][1])
	}
}

func TestUsageExplainsItselfToTheCustomer(t *testing.T) {
	// A figure larger than the provider's dashboard has to be explainable,
	// or every invoice becomes a support ticket.
	r := usage.Report{
		From: "2026-08-01T00:00:00Z", To: "2026-09-01T00:00:00Z",
		Total: usage.Day{Received: 100, Rejected: 7, Normalised: 88},
	}
	text := r.Reconciliation()
	for _, want := range []string{
		"100 events received",
		"provider's own dashboard",
		"7 of these failed signature verification",
		"mapping_complete=false",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the reconciliation note does not mention %q:\n%s", want, text)
		}
	}
}

func TestUsageByProviderIsWhatGetsReconciled(t *testing.T) {
	m, s, ep := usageSetup(t)
	ctx := context.Background()
	at := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)

	stripeEP := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "stripe",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "stripe", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, stripeEP), "stripe endpoint")

	for i := 0; i < 3; i++ {
		storeRawEvent(t, s, ep, "paystack", at, true)
		storeRawEvent(t, s, ep, "paystack", at.Add(24*time.Hour), true)
	}
	storeRawEvent(t, s, stripeEP, "stripe", at, true)

	r, err := m.Usage(ctx, tenantA, at.Add(-time.Hour), at.Add(72*time.Hour))
	mustNoErr(t, err, "metering")

	byProvider := r.ByProvider()
	if len(byProvider) != 2 {
		t.Fatalf("%d providers, want 2", len(byProvider))
	}
	// Sorted, so an invoice generated twice looks the same both times.
	if byProvider[0].Provider != "paystack" || byProvider[0].Received != 6 {
		t.Errorf("paystack = %+v", byProvider[0])
	}
	if byProvider[1].Provider != "stripe" || byProvider[1].Received != 1 {
		t.Errorf("stripe = %+v", byProvider[1])
	}
}
