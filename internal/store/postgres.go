package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// Postgres is the production store.
//
// Two things here are not obvious and are load-bearing. The first is that
// every tenant-scoped query carries its tenant in the WHERE clause *and*
// relies on row-level security underneath — belt and braces, because the
// query is written by a person and the policy is not (§8.1). The second is
// that raw_events is partitioned by month, so queries that can carry a time
// bound do, and the ones that cannot are the ones this file works hardest to
// avoid.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres connects and verifies the schema is present.
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing the database URL: %w", err)
	}

	// The receiver's whole budget is 50 ms and most of it is one INSERT, so
	// the pool is sized to avoid queuing rather than to be frugal. A
	// connection wait is indistinguishable from a slow database in the
	// latency histogram, and far harder to diagnose.
	if cfg.MaxConns < 10 {
		cfg.MaxConns = 25
	}
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database is not reachable: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

// NewPostgresFromPool wraps an existing pool, for tests and for a caller that
// already manages connections.
func NewPostgresFromPool(pool *pgxpool.Pool) *Postgres { return &Postgres{pool: pool} }

// Pool exposes the underlying pool for migrations and diagnostics.
func (p *Postgres) Pool() *pgxpool.Pool { return p.pool }

// Health is the receiver's readiness probe and nothing more: can a row be
// written. It deliberately says nothing about the dispatcher (§11.1).
func (p *Postgres) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var one int
	if err := p.pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("database query failed: %w", err)
	}
	return nil
}

// Close releases the pool.
func (p *Postgres) Close() error {
	p.pool.Close()
	return nil
}

// mapError turns a Postgres error into one of the sentinel errors callers
// distinguish.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("%w: %s", ErrDuplicate, pgErr.ConstraintName)
		case "23503": // foreign_key_violation
			return fmt.Errorf("%w: %s", ErrNotFound, pgErr.ConstraintName)
		case "40001", "40P01": // serialization_failure, deadlock_detected
			return fmt.Errorf("%w: %s", ErrConflict, pgErr.Message)
		}
	}
	return err
}

// --- Tenants ---

func (p *Postgres) CreateTenant(ctx context.Context, t domain.Tenant) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO tenants (id, slug, name, created_at) VALUES ($1,$2,$3,$4)`,
		t.ID, t.Slug, t.Name, orNow(t.CreatedAt))
	return mapError(err)
}

func (p *Postgres) GetTenant(ctx context.Context, tenantID string) (domain.Tenant, error) {
	return p.scanTenant(ctx, `WHERE id = $1`, tenantID)
}

func (p *Postgres) GetTenantBySlug(ctx context.Context, slug string) (domain.Tenant, error) {
	return p.scanTenant(ctx, `WHERE slug = $1`, slug)
}

func (p *Postgres) scanTenant(ctx context.Context, where string, arg any) (domain.Tenant, error) {
	var t domain.Tenant
	err := p.pool.QueryRow(ctx,
		`SELECT id, slug, name, created_at FROM tenants `+where, arg).
		Scan(&t.ID, &t.Slug, &t.Name, &t.CreatedAt)
	return t, mapError(err)
}

func (p *Postgres) ListTenants(ctx context.Context) ([]domain.Tenant, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, slug, name, created_at FROM tenants ORDER BY slug`)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []domain.Tenant
	for rows.Next() {
		var t domain.Tenant
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.CreatedAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, t)
	}
	return out, mapError(rows.Err())
}

// --- Endpoints ---

const endpointColumns = `id, tenant_id, provider, environment, receiver_token, secret_ref,
	adapter_name, adapter_config, allowed_source_cidrs, enabled, created_at, rotated_at`

func (p *Postgres) CreateEndpoint(ctx context.Context, e domain.Endpoint) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO endpoints (`+endpointColumns+`)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		e.ID, e.TenantID, e.Provider, string(e.Environment), e.ReceiverToken, e.SecretRef,
		e.AdapterName, nilBytes(e.AdapterConfig), orEmptySlice(e.AllowedSourceCIDRs), e.Enabled,
		orNow(e.CreatedAt), nilTime(e.RotatedAt))
	return mapError(err)
}

func (p *Postgres) GetEndpoint(ctx context.Context, tenantID, endpointID string) (domain.Endpoint, error) {
	// Scoped in the query and again by row-level security. A missing row and
	// another tenant's row produce the same ErrNotFound.
	row := p.pool.QueryRow(ctx,
		`SELECT `+endpointColumns+` FROM endpoints WHERE tenant_id = $1 AND id = $2`,
		tenantID, endpointID)
	return scanEndpoint(row)
}

func (p *Postgres) ListEndpoints(ctx context.Context, tenantID string) ([]domain.Endpoint, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+endpointColumns+` FROM endpoints WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []domain.Endpoint
	for rows.Next() {
		e, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, mapError(rows.Err())
}

func (p *Postgres) UpdateEndpoint(ctx context.Context, tenantID string, e domain.Endpoint) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE endpoints SET provider=$3, environment=$4, receiver_token=$5, secret_ref=$6,
		   adapter_name=$7, adapter_config=$8, allowed_source_cidrs=$9, enabled=$10, rotated_at=$11
		 WHERE tenant_id=$1 AND id=$2`,
		tenantID, e.ID, e.Provider, string(e.Environment), e.ReceiverToken, e.SecretRef,
		e.AdapterName, nilBytes(e.AdapterConfig), orEmptySlice(e.AllowedSourceCIDRs), e.Enabled, nilTime(e.RotatedAt))
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) DeleteEndpoint(ctx context.Context, tenantID, endpointID string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM endpoints WHERE tenant_id=$1 AND id=$2`, tenantID, endpointID)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ResolveReceiver is the receiver's hot path.
//
// One query, one index, and every component of the URL in the predicate. The
// token alone would be enough to find the row; requiring the provider and
// environment to match as well means a token issued for one endpoint cannot
// be replayed against another — the URL is the credential's scope, not just
// its address.
func (p *Postgres) ResolveReceiver(ctx context.Context, tenantSlug, provider, env, token string) (domain.Endpoint, domain.Tenant, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT e.id, e.tenant_id, e.provider, e.environment, e.receiver_token, e.secret_ref,
		        e.adapter_name, e.adapter_config, e.allowed_source_cidrs, e.enabled, e.created_at, e.rotated_at,
		        t.id, t.slug, t.name, t.created_at
		   FROM endpoints e
		   JOIN tenants t ON t.id = e.tenant_id
		  WHERE e.receiver_token = $1 AND t.slug = $2 AND e.provider = $3 AND e.environment = $4`,
		token, tenantSlug, provider, env)

	var (
		e      domain.Endpoint
		t      domain.Tenant
		envStr string
		cfg    []byte
		rot    *time.Time
	)
	err := row.Scan(&e.ID, &e.TenantID, &e.Provider, &envStr, &e.ReceiverToken, &e.SecretRef,
		&e.AdapterName, &cfg, &e.AllowedSourceCIDRs, &e.Enabled, &e.CreatedAt, &rot,
		&t.ID, &t.Slug, &t.Name, &t.CreatedAt)
	if err != nil {
		return domain.Endpoint{}, domain.Tenant{}, mapError(err)
	}
	e.Environment = domain.Environment(envStr)
	e.AdapterConfig = cfg
	if rot != nil {
		e.RotatedAt = *rot
	}
	return e, t, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanEndpoint(row scanner) (domain.Endpoint, error) {
	var (
		e      domain.Endpoint
		envStr string
		cfg    []byte
		rot    *time.Time
	)
	err := row.Scan(&e.ID, &e.TenantID, &e.Provider, &envStr, &e.ReceiverToken, &e.SecretRef,
		&e.AdapterName, &cfg, &e.AllowedSourceCIDRs, &e.Enabled, &e.CreatedAt, &rot)
	if err != nil {
		return domain.Endpoint{}, mapError(err)
	}
	e.Environment = domain.Environment(envStr)
	e.AdapterConfig = cfg
	if rot != nil {
		e.RotatedAt = *rot
	}
	return e, nil
}

func orNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t.UTC()
}

func nilTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// orEmptySlice keeps a nil Go slice from becoming a SQL NULL. The column is
// NOT NULL with a '{}' default, and the default only applies when the column
// is omitted — passing nil explicitly is passing NULL.
func orEmptySlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nilBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nilString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// placeholders builds "$n,$n+1,…" for a variable-length IN clause.
func placeholders(start, n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("$%d", start+i)
	}
	return strings.Join(parts, ",")
}
