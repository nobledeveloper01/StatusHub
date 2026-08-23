package tests

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/migrate"
	"github.com/nobledeveloper01/StatusHub/internal/retention"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

func retentionSetup(t *testing.T, now time.Time) (*retention.Manager, *store.Postgres, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("STATUSHUB_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("STATUSHUB_TEST_DATABASE_URL is not set; skipping the partition tests")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	mustNoErr(t, err, "connecting")
	t.Cleanup(pool.Close)

	_, err = pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)
	mustNoErr(t, err, "resetting the schema")
	_, err = migrate.Up(ctx, pool)
	mustNoErr(t, err, "migrating")

	s := store.NewPostgresFromPool(pool)
	mustNoErr(t, s.CreateTenant(ctx, domain.Tenant{ID: tenantA, Slug: slugA, Name: "Acme"}), "tenant")

	return retention.New(pool, func() time.Time { return now }), s, pool
}

func TestRetentionProvisionsAheadAndIsIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	m, _, _ := retentionSetup(t, now)
	ctx := context.Background()

	created, err := m.Provision(ctx)
	mustNoErr(t, err, "provisioning")
	// Current month plus three ahead, so the job can be broken for two months
	// and nobody is harmed.
	if len(created) != retention.AheadMonths+1 {
		t.Fatalf("created %v, want %d partitions", created, retention.AheadMonths+1)
	}

	// Two replicas running it at once must not race into a duplicate-relation
	// error that looks like a code bug.
	again, err := m.Provision(ctx)
	mustNoErr(t, err, "provisioning again")
	if len(again) != 0 {
		t.Fatalf("a second run created %v; it must be idempotent", again)
	}

	parts, err := m.List(ctx)
	mustNoErr(t, err, "listing")
	var named int
	for _, p := range parts {
		if !p.From.IsZero() {
			named++
		}
	}
	if named != retention.AheadMonths+1 {
		t.Errorf("%d ranged partitions listed, want %d", named, retention.AheadMonths+1)
	}
}

func TestRetentionRoutesEventsIntoTheRightPartition(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	m, s, pool := retentionSetup(t, now)
	ctx := context.Background()
	_, err := m.Provision(ctx)
	mustNoErr(t, err, "provisioning")

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "endpoint")

	mustNoErr(t, s.PutRawEvent(ctx, domain.RawEvent{
		ID: domain.NewID(domain.PrefixRawEvent), TenantID: tenantA, EndpointID: ep.ID,
		Provider: "paystack", Body: []byte(`{}`), BodySHA256: "h",
		SignatureValid: true, ReceivedAt: now,
	}), "storing an event in the current month")

	var n int64
	mustNoErr(t, pool.QueryRow(ctx, `SELECT count(*) FROM raw_events_2026_08`).Scan(&n),
		"counting the August partition")
	if n != 1 {
		t.Fatalf("the August partition holds %d rows, want 1", n)
	}

	// And the default partition is empty, which is the healthy state.
	rows, err := m.DefaultPartitionRows(ctx)
	mustNoErr(t, err, "counting the default partition")
	if rows != 0 {
		t.Errorf("%d rows landed in the default partition", rows)
	}
}

func TestRetentionRecoversRowsFromTheDefaultPartition(t *testing.T) {
	// A missed provisioning job must degrade into slow queries rather than
	// into refusing an event. But left there, those rows can never be dropped
	// by retention — so the next run of the job has to move them home, or a
	// missed job becomes permanently unrecoverable.
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	m, s, _ := retentionSetup(t, now)
	ctx := context.Background()

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "endpoint")

	// No partitions yet, so this lands in the catch-all — and, crucially, is
	// stored rather than refused.
	raw := domain.RawEvent{
		ID: domain.NewID(domain.PrefixRawEvent), TenantID: tenantA, EndpointID: ep.ID,
		Provider: "paystack", Body: []byte(`{}`), BodySHA256: "h",
		SignatureValid: true, ReceivedAt: now,
	}
	mustNoErr(t, s.PutRawEvent(ctx, raw), "an event must still be stored when no partition exists for it")

	stranded, err := m.DefaultPartitionRows(ctx)
	mustNoErr(t, err, "counting the default partition")
	if stranded != 1 {
		t.Fatalf("%d rows in the default partition before recovery, want 1", stranded)
	}

	report, err := m.Run(ctx, 30*24*time.Hour, false)
	mustNoErr(t, err, "running the job")

	// Postgres refuses to create a partition overlapping rows in the default
	// one, so the job detaches, creates, moves and reattaches. Without that,
	// this month could never be provisioned at all.
	if report.DefaultPartitionRows != 0 {
		t.Fatalf("%d rows left stranded after the job ran: %s", report.DefaultPartitionRows, report.Warning)
	}
	if report.Warning != "" {
		t.Errorf("a successful recovery still warned: %q", report.Warning)
	}

	// And the event is intact, in its proper partition.
	got, err := s.GetRawEvent(ctx, tenantA, raw.ID)
	mustNoErr(t, err, "the recovered event must still be readable")
	if got.ID != raw.ID {
		t.Errorf("recovered event = %+v", got)
	}
}

func TestRetentionWarnsAboutRowsItCannotRecover(t *testing.T) {
	// A row dated outside every provisionable range — a provider replaying
	// something ancient, or a clock badly wrong — cannot be moved home, and
	// cannot be dropped by retention either. That needs a human.
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	m, s, _ := retentionSetup(t, now)
	ctx := context.Background()

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "endpoint")
	mustNoErr(t, s.PutRawEvent(ctx, domain.RawEvent{
		ID: domain.NewID(domain.PrefixRawEvent), TenantID: tenantA, EndpointID: ep.ID,
		Provider: "paystack", Body: []byte(`{}`), BodySHA256: "h",
		SignatureValid: true, ReceivedAt: now.AddDate(-2, 0, 0),
	}), "an ancient event must still be stored")

	report, err := m.Run(ctx, 30*24*time.Hour, false)
	mustNoErr(t, err, "running the job")
	if report.DefaultPartitionRows != 1 {
		t.Fatalf("default partition rows = %d, want 1", report.DefaultPartitionRows)
	}
	if report.Warning == "" {
		t.Fatal("a row that cannot be recovered produced no warning")
	}
	if !containsAll(report.Warning, "cannot be dropped by retention") {
		t.Errorf("the warning does not explain the consequence: %q", report.Warning)
	}
}

func TestRetentionDropsOnlyFullyExpiredPartitions(t *testing.T) {
	// A partition straddling the retention boundary still holds rows a tenant
	// is entitled to. Dropping it to reclaim space would delete records
	// inside their retention period, which is a compliance failure rather
	// than an optimisation.
	base := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	m, _, pool := retentionSetup(t, base)
	ctx := context.Background()

	// Provision January through April 2026.
	_, err := m.Provision(ctx)
	mustNoErr(t, err, "provisioning")

	// Now it is 15 April. With 60 days of retention the cutoff is 14
	// February: January is entirely expired, February straddles it.
	later := retention.New(pool, func() time.Time { return time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC) })

	planned, err := later.Prune(ctx, 60*24*time.Hour, true)
	mustNoErr(t, err, "dry run")
	if len(planned) != 1 || planned[0].Name != "raw_events_2026_01" {
		t.Fatalf("the dry run would drop %+v; only January is entirely expired", planned)
	}

	// The dry run must not have dropped anything.
	parts, err := later.List(ctx)
	mustNoErr(t, err, "listing after the dry run")
	if !hasPartition(parts, "raw_events_2026_01") {
		t.Fatal("a dry run dropped a partition")
	}

	dropped, err := later.Prune(ctx, 60*24*time.Hour, false)
	mustNoErr(t, err, "pruning")
	if len(dropped) != 1 {
		t.Fatalf("dropped %+v", dropped)
	}

	parts, err = later.List(ctx)
	mustNoErr(t, err, "listing after the prune")
	if hasPartition(parts, "raw_events_2026_01") {
		t.Error("January was not dropped")
	}
	if !hasPartition(parts, "raw_events_2026_02") {
		t.Error("February was dropped, but it straddles the retention boundary and still holds retained rows")
	}
}

func TestRetentionNeverDropsTheDefaultPartition(t *testing.T) {
	// Its contents could be from any period, so it can never be judged
	// expired.
	m, _, pool := retentionSetup(t, time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC))
	ctx := context.Background()
	_, err := m.Provision(ctx)
	mustNoErr(t, err, "provisioning")

	future := retention.New(pool, func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) })
	_, err = future.Prune(ctx, 24*time.Hour, false)
	mustNoErr(t, err, "pruning far in the future")

	parts, err := future.List(ctx)
	mustNoErr(t, err, "listing")
	if !hasPartition(parts, "raw_events_default") {
		t.Fatal("the default partition was dropped")
	}
}

func TestRetentionRefusesAnAbsurdWindow(t *testing.T) {
	// A retention shorter than a day would drop the current partition and
	// take today's events with it.
	m, _, _ := retentionSetup(t, time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC))
	if _, err := m.Prune(context.Background(), time.Hour, true); err == nil {
		t.Fatal("a one-hour retention window was accepted")
	}
}

func hasPartition(parts []retention.Partition, name string) bool {
	for _, p := range parts {
		if p.Name == name {
			return true
		}
	}
	return false
}
