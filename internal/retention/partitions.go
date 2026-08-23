// Package retention provisions and drops the monthly partitions on
// raw_events, and enforces each tenant's retention window.
//
// raw_events is the fastest-growing table in the system and the only one
// whose rows cannot be regenerated from anywhere — the provider will not
// resend. Partitioning is what makes retention a DROP PARTITION rather than a
// DELETE that leaves the table bloated and autovacuum running for a week.
//
// Nothing created those partitions until now. The default partition catches
// anything outside the provisioned ranges, so a missed job degrades into slow
// queries rather than into refusing to store a provider's event — but rows in
// the default partition cannot be dropped by retention, so it is an alarm
// rather than a fallback to rely on.
package retention

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AheadMonths is how far ahead partitions are provisioned.
//
// Three. The job runs daily, so one month would be ample — but the failure
// mode of running out is that every event lands in the default partition,
// silently, and the operator only discovers it when retention cannot drop
// anything. Three months means the job can be broken for two of them and
// nobody is harmed.
const AheadMonths = 3

// Manager provisions and prunes partitions.
type Manager struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// New builds a Manager.
func New(pool *pgxpool.Pool, now func() time.Time) *Manager {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Manager{pool: pool, now: now}
}

// Partition describes one monthly range.
type Partition struct {
	Name  string    `json:"name"`
	From  time.Time `json:"from"`
	To    time.Time `json:"to"`
	Rows  int64     `json:"approximate_rows,omitempty"`
	Bytes int64     `json:"bytes,omitempty"`
}

func partitionName(month time.Time) string {
	return fmt.Sprintf("raw_events_%04d_%02d", month.Year(), int(month.Month()))
}

func monthStart(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// Provision creates any missing partition from the current month through
// AheadMonths, and returns the ones it created.
//
// Idempotent, because it runs daily and because two replicas running it at
// once must not race into a duplicate-relation error that looks like a code
// bug.
func (m *Manager) Provision(ctx context.Context) ([]string, error) {
	start := monthStart(m.now())
	var created []string

	for i := 0; i <= AheadMonths; i++ {
		from := start.AddDate(0, i, 0)
		to := from.AddDate(0, 1, 0)
		name := partitionName(from)

		exists, err := m.exists(ctx, name)
		if err != nil {
			return created, err
		}
		if exists {
			continue
		}

		if err := m.createPartition(ctx, name, from, to); err != nil {
			return created, err
		}
		created = append(created, name)
	}
	return created, nil
}

// createPartition adds one month, recovering rows that landed in the default
// partition while this month had no home.
//
// Postgres refuses to create a partition whose range overlaps rows already in
// the default partition, and that refusal is exactly what happens after the
// provisioning job has been down: events kept arriving, landed in the
// catch-all, and now the month cannot be provisioned at all. Left unhandled,
// a missed job becomes permanently unrecoverable and every subsequent event
// piles into a partition retention can never drop.
//
// So the recovery is part of the job rather than a runbook step: detach the
// default, create the month, move its rows in, reattach. All in one
// transaction, because a crash with the default detached would mean events
// arriving in that window are refused outright — the one failure this system
// does not accept.
func (m *Manager) createPartition(ctx context.Context, name string, from, to time.Time) error {
	// The offset is explicit. A bare '2026-08-01' is interpreted in the
	// session's timezone, so the same statement run from a BST server and a
	// UTC one produces boundaries an hour apart — and two provisioning runs
	// under different session timezones would leave an hour-wide gap or
	// overlap between adjacent months.
	create := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s PARTITION OF raw_events FOR VALUES FROM ('%s') TO ('%s')`,
		name, from.UTC().Format("2006-01-02 15:04:05-07"), to.UTC().Format("2006-01-02 15:04:05-07"))

	// CREATE TABLE … PARTITION OF takes an ACCESS EXCLUSIVE lock on the
	// parent. Brief for an empty partition, which is why partitions are
	// created months ahead rather than on first write.
	if _, err := m.pool.Exec(ctx, create); err == nil {
		return nil
	} else if !isDefaultOverlap(err) {
		return fmt.Errorf("creating partition %s: %w", name, err)
	}

	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `ALTER TABLE raw_events DETACH PARTITION raw_events_default`); err != nil {
		return fmt.Errorf("detaching the default partition to provision %s: %w", name, err)
	}
	if _, err := tx.Exec(ctx, create); err != nil {
		return fmt.Errorf("creating partition %s after detaching the default: %w", name, err)
	}
	if _, err := tx.Exec(ctx,
		`WITH moved AS (
		   DELETE FROM raw_events_default WHERE received_at >= $1 AND received_at < $2 RETURNING *
		 )
		 INSERT INTO raw_events SELECT * FROM moved`, from, to); err != nil {
		return fmt.Errorf("moving rows out of the default partition into %s: %w", name, err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE raw_events ATTACH PARTITION raw_events_default DEFAULT`); err != nil {
		return fmt.Errorf("reattaching the default partition after provisioning %s: %w", name, err)
	}
	return tx.Commit(ctx)
}

// isDefaultOverlap recognises the error Postgres raises when rows in the
// default partition fall inside a range being created.
func isDefaultOverlap(err error) bool {
	return err != nil && strings.Contains(err.Error(), "default partition")
}

// Prune drops partitions entirely older than the retention window.
//
// A partition is dropped only when its *whole range* is past the window. A
// partition straddling the boundary still holds rows a tenant is entitled to,
// and dropping it to reclaim space would delete records inside their
// retention period — which is a compliance failure, not an optimisation.
func (m *Manager) Prune(ctx context.Context, retain time.Duration, dryRun bool) ([]Partition, error) {
	if retain < 24*time.Hour {
		// A retention shorter than a day would drop the current partition and
		// take today's events with it. Refused rather than clamped, because a
		// caller asking for this has made a mistake worth surfacing.
		return nil, fmt.Errorf("retention must be at least 24 hours, got %s", retain)
	}
	cutoff := m.now().Add(-retain)

	partitions, err := m.List(ctx)
	if err != nil {
		return nil, err
	}

	var dropped []Partition
	for _, p := range partitions {
		// A partition with no parsed range is the default one. Its contents
		// could be from any period, so it can never be judged expired —
		// and a zero To would otherwise compare as "before the cutoff" and
		// silently delete everything the provisioning job failed to route.
		if p.From.IsZero() || p.To.IsZero() {
			continue
		}
		if !p.To.Before(cutoff) {
			continue
		}
		dropped = append(dropped, p)
		if dryRun {
			continue
		}
		if _, err := m.pool.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s`, p.Name)); err != nil {
			return dropped, fmt.Errorf("dropping partition %s: %w", p.Name, err)
		}
	}
	return dropped, nil
}

// List returns the provisioned partitions with their sizes, newest first.
func (m *Manager) List(ctx context.Context) ([]Partition, error) {
	rows, err := m.pool.Query(ctx,
		`SELECT c.relname,
		        pg_catalog.pg_get_expr(c.relpartbound, c.oid),
		        COALESCE(c.reltuples, 0)::bigint,
		        pg_total_relation_size(c.oid)
		   FROM pg_class c
		   JOIN pg_inherits i ON i.inhrelid = c.oid
		   JOIN pg_class parent ON parent.oid = i.inhparent
		  WHERE parent.relname = 'raw_events'
		  ORDER BY c.relname DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Partition
	for rows.Next() {
		var (
			name, bound string
			tuples      int64
			bytes       int64
		)
		if err := rows.Scan(&name, &bound, &tuples, &bytes); err != nil {
			return nil, err
		}
		p := Partition{Name: name, Rows: tuples, Bytes: bytes}
		// The default partition has no range, and must never be treated as
		// droppable — its contents could be from any period.
		if from, to, ok := parseBound(bound); ok {
			p.From, p.To = from, to
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// parseBound reads `FOR VALUES FROM ('2026-08-01 …') TO ('2026-09-01 …')`.
func parseBound(bound string) (from, to time.Time, ok bool) {
	var quoted []string
	inQuote := false
	current := ""
	for _, r := range bound {
		switch {
		case r == '\'':
			if inQuote {
				quoted = append(quoted, current)
				current = ""
			}
			inQuote = !inQuote
		case inQuote:
			current += string(r)
		}
	}
	if len(quoted) != 2 {
		return time.Time{}, time.Time{}, false
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05-07", "2006-01-02 15:04:05", "2006-01-02",
	} {
		f, err1 := time.Parse(layout, quoted[0])
		t, err2 := time.Parse(layout, quoted[1])
		if err1 == nil && err2 == nil {
			return f.UTC(), t.UTC(), true
		}
	}
	return time.Time{}, time.Time{}, false
}

// DefaultPartitionRows counts what landed in the catch-all.
//
// This is the alarm, not a statistic. Anything in the default partition
// arrived outside every provisioned range, which means the provisioning job
// has not run — and those rows cannot be dropped by retention, so they
// accumulate silently until somebody notices the disk.
func (m *Manager) DefaultPartitionRows(ctx context.Context) (int64, error) {
	var n int64
	err := m.pool.QueryRow(ctx, `SELECT count(*) FROM raw_events_default`).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (m *Manager) exists(ctx context.Context, name string) (bool, error) {
	var found bool
	err := m.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1 AND relkind = 'r')`, name).Scan(&found)
	return found, err
}

// Report is what the daily job logs and the dashboard renders.
type Report struct {
	Created              []string    `json:"created"`
	Dropped              []Partition `json:"dropped"`
	Partitions           []Partition `json:"partitions"`
	DefaultPartitionRows int64       `json:"default_partition_rows"`
	TotalBytes           int64       `json:"total_bytes"`

	// Warning is set when something needs a human. It is a single string
	// rather than a flag because the thing an operator needs is the sentence,
	// not a boolean they then have to interpret.
	Warning string `json:"warning,omitempty"`
}

// Run provisions, prunes and reports. This is the whole daily job.
func (m *Manager) Run(ctx context.Context, retain time.Duration, dryRun bool) (Report, error) {
	var r Report

	created, err := m.Provision(ctx)
	if err != nil {
		return r, err
	}
	r.Created = created

	dropped, err := m.Prune(ctx, retain, dryRun)
	if err != nil {
		return r, err
	}
	r.Dropped = dropped

	r.Partitions, err = m.List(ctx)
	if err != nil {
		return r, err
	}
	for _, p := range r.Partitions {
		r.TotalBytes += p.Bytes
	}

	r.DefaultPartitionRows, err = m.DefaultPartitionRows(ctx)
	if err != nil {
		return r, err
	}
	if r.DefaultPartitionRows > 0 {
		r.Warning = fmt.Sprintf(
			"%d rows are in the default partition, which means they arrived outside every provisioned "+
				"range. They cannot be dropped by retention and will accumulate until moved. "+
				"Check that this job has been running.", r.DefaultPartitionRows)
	}
	return r, nil
}
