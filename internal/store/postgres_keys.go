package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nobledeveloper01/StatusHub/internal/auth"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// PostgresKeys persists API keys.
//
// It lives in the store package rather than in auth so that auth stays free
// of a database dependency — the hashing and comparison logic is the part
// worth being able to test and reason about in isolation.
type PostgresKeys struct {
	pool *pgxpool.Pool
}

// NewPostgresKeys wraps a pool.
func NewPostgresKeys(pool *pgxpool.Pool) *PostgresKeys { return &PostgresKeys{pool: pool} }

const keyColumns = `id, tenant_id, prefix, hash, environment, role, name,
	created_at, expires_at, last_used_at, revoked_at`

func (s *PostgresKeys) PutKey(ctx context.Context, k auth.Key) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO api_keys (`+keyColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		k.ID, k.TenantID, k.Prefix, k.Hash, string(k.Environment), string(k.Role), k.Name,
		orNow(k.CreatedAt), nilTime(k.ExpiresAt), nilTime(k.LastUsed), nilTime(k.RevokedAt))
	return mapError(err)
}

// GetKeyByPrefix is the authentication path's lookup, and the only query in
// the system that is not tenant-scoped — because the tenant is what it
// resolves.
func (s *PostgresKeys) GetKeyByPrefix(ctx context.Context, prefix string) (auth.Key, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+keyColumns+` FROM api_keys WHERE prefix = $1`, prefix)
	k, err := scanKey(row)
	if errors.Is(err, ErrNotFound) {
		return auth.Key{}, auth.ErrKeyNotFound
	}
	return k, err
}

func (s *PostgresKeys) ListKeys(ctx context.Context, tenantID string) ([]auth.Key, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+keyColumns+` FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []auth.Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, mapError(rows.Err())
}

func (s *PostgresKeys) RevokeKey(ctx context.Context, tenantID, keyID string, at time.Time) error {
	// Scoped to the tenant, so one tenant cannot revoke another's key by
	// guessing an identifier.
	tag, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET revoked_at = $3 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`,
		tenantID, keyID, at)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrKeyNotFound
	}
	return nil
}

// TouchKey records last use.
//
// Best-effort and deliberately not in the request's critical path: it is a
// write on every authenticated call, and the useful thing it buys — an owner
// being able to see which keys nobody has used in six months — is not worth
// failing a request over.
func (s *PostgresKeys) TouchKey(ctx context.Context, keyID string, at time.Time) error {
	// Only written when it moves by more than a minute. Otherwise a busy
	// integration turns one row into the most-written row in the database.
	_, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET last_used_at = $2
		  WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < $2 - interval '1 minute')`,
		keyID, at)
	return mapError(err)
}

func scanKey(row scanner) (auth.Key, error) {
	var (
		k                      auth.Key
		env, role              string
		expires, lastUsed, rev *time.Time
	)
	err := row.Scan(&k.ID, &k.TenantID, &k.Prefix, &k.Hash, &env, &role, &k.Name,
		&k.CreatedAt, &expires, &lastUsed, &rev)
	if err != nil {
		return auth.Key{}, mapError(err)
	}
	k.Environment = domain.Environment(env)
	k.Role = auth.Role(role)
	for _, pair := range []struct {
		src *time.Time
		dst *time.Time
	}{{expires, &k.ExpiresAt}, {lastUsed, &k.LastUsed}, {rev, &k.RevokedAt}} {
		if pair.src != nil {
			*pair.dst = *pair.src
		}
	}
	return k, nil
}

// Compile-time proof that this satisfies the interface the API depends on.
var _ auth.KeyStore = (*PostgresKeys)(nil)
