// Package migrate applies the SQL in migrations/.
//
// Migrations are embedded in the binary rather than read from disk, so the
// schema a binary expects and the schema it can create are the same artefact.
// A container shipped without its migrations directory is a container that
// starts, connects, and fails on the first query.
package migrate

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed sql/*.sql
var files embed.FS

// Migration is one versioned change.
type Migration struct {
	Version string
	Up      string
	Down    string
}

// Status reports what has run and what has not.
type Status struct {
	Version   string    `json:"version"`
	Applied   bool      `json:"applied"`
	AppliedAt time.Time `json:"applied_at,omitempty"`
}

// Load reads the embedded migrations, sorted by version.
func Load() ([]Migration, error) {
	entries, err := fs.ReadDir(files, "sql")
	if err != nil {
		return nil, err
	}

	byVersion := map[string]*Migration{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		body, err := files.ReadFile("sql/" + name)
		if err != nil {
			return nil, err
		}
		switch {
		case strings.HasSuffix(name, ".up.sql"):
			v := strings.TrimSuffix(name, ".up.sql")
			get(byVersion, v).Up = string(body)
		case strings.HasSuffix(name, ".down.sql"):
			v := strings.TrimSuffix(name, ".down.sql")
			get(byVersion, v).Down = string(body)
		}
	}

	out := make([]Migration, 0, len(byVersion))
	for _, m := range byVersion {
		if m.Up == "" {
			// A down with no up is a migration that can only ever be undone,
			// which is a packaging mistake worth failing on rather than
			// skipping.
			return nil, fmt.Errorf("migration %s has a down but no up", m.Version)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

func get(m map[string]*Migration, v string) *Migration {
	if _, ok := m[v]; !ok {
		m[v] = &Migration{Version: v}
	}
	return m[v]
}

// Up applies every pending migration.
//
// Each runs in its own transaction and records itself in the same
// transaction, so a migration either happened and is recorded or did neither.
// A schema change recorded as applied that partly failed is the worst state
// this package could produce: every subsequent run would skip it.
func Up(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	if err := ensureLedger(ctx, pool); err != nil {
		return nil, err
	}
	migrations, err := Load()
	if err != nil {
		return nil, err
	}
	applied, err := appliedVersions(ctx, pool)
	if err != nil {
		return nil, err
	}

	var ran []string
	for _, m := range migrations {
		if _, done := applied[m.Version]; done {
			continue
		}
		if err := runOne(ctx, pool, m); err != nil {
			return ran, fmt.Errorf("migration %s: %w", m.Version, err)
		}
		ran = append(ran, m.Version)
	}
	return ran, nil
}

func runOne(ctx context.Context, pool *pgxpool.Pool, m Migration) error {
	// One migration at a time across every replica. Two processes starting
	// together and both running 0002 is how a deploy produces a duplicate
	// index error that looks like a code bug.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('statushub:migrate'))`); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtext('statushub:migrate'))`)
	}()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, m.Up); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, m.Version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// StatusOf reports each migration's state.
func StatusOf(ctx context.Context, pool *pgxpool.Pool) ([]Status, error) {
	if err := ensureLedger(ctx, pool); err != nil {
		return nil, err
	}
	migrations, err := Load()
	if err != nil {
		return nil, err
	}
	applied, err := appliedVersions(ctx, pool)
	if err != nil {
		return nil, err
	}

	out := make([]Status, 0, len(migrations))
	for _, m := range migrations {
		s := Status{Version: m.Version}
		if at, ok := applied[m.Version]; ok {
			s.Applied, s.AppliedAt = true, at
		}
		out = append(out, s)
	}
	return out, nil
}

// Pending reports whether any migration has not run. The server calls it at
// start-up and refuses to serve if the answer is yes: a binary running
// against an older schema fails in ways that look like data corruption.
func Pending(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	statuses, err := StatusOf(ctx, pool)
	if err != nil {
		return nil, err
	}
	var pending []string
	for _, s := range statuses {
		if !s.Applied {
			pending = append(pending, s.Version)
		}
	}
	return pending, nil
}

func ensureLedger(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
		   version    TEXT PRIMARY KEY,
		   applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`)
	return err
}

func appliedVersions(ctx context.Context, pool *pgxpool.Pool) (map[string]time.Time, error) {
	rows, err := pool.Query(ctx, `SELECT version, applied_at FROM schema_migrations`)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return map[string]time.Time{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	out := map[string]time.Time{}
	for rows.Next() {
		var v string
		var at time.Time
		if err := rows.Scan(&v, &at); err != nil {
			return nil, err
		}
		out[v] = at
	}
	return out, rows.Err()
}
